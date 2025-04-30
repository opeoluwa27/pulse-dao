;; proposal-manager.clar
;; A contract for managing health cooperative governance proposals in the PulseDAO platform.
;; This contract handles the complete lifecycle of governance proposals specific to healthcare management,
;; from creation to execution, with appropriate security and access controls.

;; ========================================
;; Constants and Error Codes
;; ========================================

;; Error constants
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-PROPOSAL-ID (err u101))
(define-constant ERR-INVALID-CATEGORY (err u102))
(define-constant ERR-INACTIVE-PROPOSAL (err u103))
(define-constant ERR-PROPOSAL-ALREADY-EXISTS (err u104))
(define-constant ERR-INSUFFICIENT-THRESHOLD (err u105))
(define-constant ERR-ALREADY-SPONSORED (err u106))
(define-constant ERR-PROPOSAL-NOT-ACTIVE (err u107))
(define-constant ERR-INVALID-STATE-TRANSITION (err u108))
(define-constant ERR-SENSITIVE-INFO-ACCESS (err u109))

;; Proposal status constants
(define-constant STATUS-DRAFT u1)
(define-constant STATUS-PENDING u2)
(define-constant STATUS-ACTIVE u3)
(define-constant STATUS-PASSED u4)
(define-constant STATUS-REJECTED u5)
(define-constant STATUS-EXECUTED u6)
(define-constant STATUS-CANCELLED u7)

;; Proposal category constants - specific to healthcare governance
(define-constant CATEGORY-FACILITY-IMPROVEMENT u1)
(define-constant CATEGORY-CARE-PROTOCOL u2)
(define-constant CATEGORY-PRACTITIONER-HIRING u3)
(define-constant CATEGORY-BUDGET-ALLOCATION u4)
(define-constant CATEGORY-EQUIPMENT-PURCHASE u5)
(define-constant CATEGORY-POLICY-CHANGE u6)
(define-constant CATEGORY-OTHER u7)

;; Governance parameters
(define-constant PROPOSAL-SUBMISSION-THRESHOLD u100) ;; Minimum tokens required to submit a proposal
(define-constant PROPOSAL-SPONSORSHIP-THRESHOLD u500) ;; Minimum tokens required to sponsor a proposal

;; ========================================
;; Data Maps and Variables
;; ========================================

;; Tracks the total number of proposals created
(define-data-var proposal-count uint u0)

;; Main proposals data structure
(define-map proposals
  uint ;; proposal-id
  {
    title: (string-ascii 100),
    description: (string-utf8 4000),
    link: (optional (string-ascii 255)),
    category: uint,
    proposer: principal,
    created-at: uint,
    status: uint,
    sponsors: (list 10 principal),
    contains-sensitive-info: bool,
    execution-params: (optional (string-utf8 1000)),
    last-updated: uint
  }
)

;; Maps principals to a list of their proposal IDs
(define-map user-proposals
  principal
  (list 100 uint)
)

;; Maps proposal IDs to their authorized viewers (used for sensitive information)
(define-map proposal-authorized-viewers
  uint ;; proposal-id
  (list 50 principal)
)

;; ========================================
;; Private Functions
;; ========================================

;; Checks if a principal has a minimum token balance
(define-private (check-token-threshold (account principal) (min-threshold uint))
  (let ((balance (unwrap-panic (contract-call? 'SP000000000000000000002Q6VF78.pox-3 get-balance account))))
    (>= balance min-threshold)
  )
)

;; Checks if a category is valid
(define-private (is-valid-category (category uint))
  (or 
    (is-eq category CATEGORY-FACILITY-IMPROVEMENT)
    (is-eq category CATEGORY-CARE-PROTOCOL)
    (is-eq category CATEGORY-PRACTITIONER-HIRING)
    (is-eq category CATEGORY-BUDGET-ALLOCATION)
    (is-eq category CATEGORY-EQUIPMENT-PURCHASE)
    (is-eq category CATEGORY-POLICY-CHANGE)
    (is-eq category CATEGORY-OTHER)
  )
)

;; Checks if a principal is authorized to view sensitive information
(define-private (is-authorized-for-sensitive-info (proposal-id uint) (viewer principal))
  (let (
    (proposal (unwrap! (map-get? proposals proposal-id) false))
    (authorized-viewers (default-to (list) (map-get? proposal-authorized-viewers proposal-id)))
  )
    (or 
      (is-eq (get proposer proposal) viewer)
      (is-some (index-of authorized-viewers viewer))
    )
  )
)

;; Adds a proposal ID to a user's proposal list
(define-private (add-to-user-proposals (user principal) (proposal-id uint))
  (let ((user-props (default-to (list) (map-get? user-proposals user))))
    (map-set user-proposals user (append user-props proposal-id))
  )
)

;; Updates the status of a proposal
(define-private (update-proposal-status (proposal-id uint) (new-status uint))
  (let ((proposal (unwrap! (map-get? proposals proposal-id) ERR-INVALID-PROPOSAL-ID)))
    (map-set proposals 
      proposal-id
      (merge proposal {
        status: new-status,
        last-updated: block-height
      })
    )
    (ok true)
  )
)

;; ========================================
;; Read-Only Functions
;; ========================================

;; Get the total number of proposals
(define-read-only (get-proposal-count)
  (var-get proposal-count)
)

;; Get a proposal by ID
(define-read-only (get-proposal (proposal-id uint))
  (let ((proposal (map-get? proposals proposal-id)))
    (if (and 
          (is-some proposal) 
          (get contains-sensitive-info (unwrap-panic proposal))
          (not (is-authorized-for-sensitive-info proposal-id tx-sender))
        )
      ;; Return redacted version if contains sensitive info and user is not authorized
      (some (merge (unwrap-panic proposal) {
        description: "This proposal contains sensitive health information. You are not authorized to view the full details.",
        execution-params: none
      }))
      ;; Return the full proposal
      proposal
    )
  )
)

;; Get proposals by status
(define-read-only (get-proposals-by-status (status uint))
  (let ((count (var-get proposal-count)))
    (filter-proposals count status)
  )
)

;; Helper function to filter proposals by status
(define-read-only (filter-proposals (max-id uint) (status uint))
  (filter check-proposal-status (generate-proposal-ids max-id))
)

;; Generate a list of proposal IDs up to max-id
(define-read-only (generate-proposal-ids (max-id uint))
  (map unwrap-panic 
    (map some-default 
      (map to-uint (generate-sequence u1 max-id)) 
      (list)
    )
  )
)

;; Check if a proposal has the given status
(define-read-only (check-proposal-status (proposal-id uint))
  (match (map-get? proposals proposal-id)
    proposal (is-eq (get status proposal) STATUS-ACTIVE)
    false
  )
)

;; Get proposals by proposer
(define-read-only (get-user-proposals (user principal))
  (default-to (list) (map-get? user-proposals user))
)

;; Get proposals by category
(define-read-only (get-proposals-by-category (category uint))
  (let ((count (var-get proposal-count)))
    (filter-by-category count category)
  )
)

;; Helper function to filter proposals by category
(define-read-only (filter-by-category (max-id uint) (category uint))
  (filter 
    (lambda (id) 
      (match (map-get? proposals id)
        proposal (is-eq (get category proposal) category)
        false
      )
    )
    (generate-proposal-ids max-id)
  )
)

;; Check if a user is authorized to view sensitive info for a proposal
(define-read-only (check-authorization (proposal-id uint) (user principal))
  (is-authorized-for-sensitive-info proposal-id user)
)

;; ========================================
;; Public Functions
;; ========================================

;; Create a new proposal
(define-public (create-proposal 
  (title (string-ascii 100))
  (description (string-utf8 4000))
  (link (optional (string-ascii 255)))
  (category uint)
  (contains-sensitive bool)
  (execution-params (optional (string-utf8 1000)))
)
  (let (
    (proposal-id (+ (var-get proposal-count) u1))
    (sender tx-sender)
  )
    ;; Check prerequisites
    (asserts! (check-token-threshold sender PROPOSAL-SUBMISSION-THRESHOLD) ERR-INSUFFICIENT-THRESHOLD)
    (asserts! (is-valid-category category) ERR-INVALID-CATEGORY)
    
    ;; Create the proposal
    (map-set proposals proposal-id {
      title: title,
      description: description,
      link: link,
      category: category,
      proposer: sender,
      created-at: block-height,
      status: STATUS-DRAFT,
      sponsors: (list sender),
      contains-sensitive-info: contains-sensitive,
      execution-params: execution-params,
      last-updated: block-height
    })
    
    ;; Update data
    (var-set proposal-count proposal-id)
    (add-to-user-proposals sender proposal-id)
    
    ;; If contains sensitive info, add proposer to authorized viewers
    (if contains-sensitive
      (map-set proposal-authorized-viewers proposal-id (list sender))
      true
    )
    
    (ok proposal-id)
  )
)

;; Submit a draft proposal to make it pending for sponsorship
(define-public (submit-proposal (proposal-id uint))
  (let (
    (proposal (unwrap! (map-get? proposals proposal-id) ERR-INVALID-PROPOSAL-ID))
    (sender tx-sender)
  )
    ;; Check prerequisites
    (asserts! (is-eq (get proposer proposal) sender) ERR-NOT-AUTHORIZED)
    (asserts! (is-eq (get status proposal) STATUS-DRAFT) ERR-INVALID-STATE-TRANSITION)
    
    ;; Update proposal status
    (update-proposal-status proposal-id STATUS-PENDING)
  )
)

;; Sponsor a pending proposal to make it active
(define-public (sponsor-proposal (proposal-id uint))
  (let (
    (proposal (unwrap! (map-get? proposals proposal-id) ERR-INVALID-PROPOSAL-ID))
    (sender tx-sender)
    (current-sponsors (get sponsors proposal))
  )
    ;; Check prerequisites
    (asserts! (is-eq (get status proposal) STATUS-PENDING) ERR-PROPOSAL-NOT-ACTIVE)
    (asserts! (not (is-some (index-of current-sponsors sender))) ERR-ALREADY-SPONSORED)
    (asserts! (check-token-threshold sender PROPOSAL-SPONSORSHIP-THRESHOLD) ERR-INSUFFICIENT-THRESHOLD)
    
    ;; Update sponsors list
    (map-set proposals 
      proposal-id
      (merge proposal {
        sponsors: (append current-sponsors sender),
        status: (if (>= (len (append current-sponsors sender)) u5) 
                  STATUS-ACTIVE 
                  (get status proposal)),
        last-updated: block-height
      })
    )
    
    (ok true)
  )
)

;; Update an existing proposal (only if in draft state)
(define-public (update-proposal
  (proposal-id uint)
  (title (string-ascii 100))
  (description (string-utf8 4000))
  (link (optional (string-ascii 255)))
  (category uint)
  (contains-sensitive bool)
  (execution-params (optional (string-utf8 1000)))
)
  (let (
    (proposal (unwrap! (map-get? proposals proposal-id) ERR-INVALID-PROPOSAL-ID))
    (sender tx-sender)
  )
    ;; Check prerequisites
    (asserts! (is-eq (get proposer proposal) sender) ERR-NOT-AUTHORIZED)
    (asserts! (is-eq (get status proposal) STATUS-DRAFT) ERR-INVALID-STATE-TRANSITION)
    (asserts! (is-valid-category category) ERR-INVALID-CATEGORY)
    
    ;; Update the proposal
    (map-set proposals proposal-id 
      (merge proposal {
        title: title,
        description: description,
        link: link,
        category: category,
        contains-sensitive-info: contains-sensitive,
        execution-params: execution-params,
        last-updated: block-height
      })
    )
    
    (ok true)
  )
)

;; Cancel a proposal (only by proposer and if not executed)
(define-public (cancel-proposal (proposal-id uint))
  (let (
    (proposal (unwrap! (map-get? proposals proposal-id) ERR-INVALID-PROPOSAL-ID))
    (sender tx-sender)
    (status (get status proposal))
  )
    ;; Check prerequisites
    (asserts! (is-eq (get proposer proposal) sender) ERR-NOT-AUTHORIZED)
    (asserts! (not (is-eq status STATUS-EXECUTED)) ERR-INVALID-STATE-TRANSITION)
    
    ;; Update the proposal
    (update-proposal-status proposal-id STATUS-CANCELLED)
  )
)

;; Execute a passed proposal
(define-public (execute-proposal (proposal-id uint))
  (let (
    (proposal (unwrap! (map-get? proposals proposal-id) ERR-INVALID-PROPOSAL-ID))
    (sender tx-sender)
  )
    ;; Check prerequisites
    (asserts! (is-eq (get status proposal) STATUS-PASSED) ERR-INVALID-STATE-TRANSITION)
    (asserts! (is-eq (get proposer proposal) sender) ERR-NOT-AUTHORIZED)
    
    ;; Update the proposal
    (update-proposal-status proposal-id STATUS-EXECUTED)
  )
)

;; Authorize a user to view sensitive information
(define-public (authorize-viewer (proposal-id uint) (viewer principal))
  (let (
    (proposal (unwrap! (map-get? proposals proposal-id) ERR-INVALID-PROPOSAL-ID))
    (sender tx-sender)
    (current-viewers (default-to (list) (map-get? proposal-authorized-viewers proposal-id)))
  )
    ;; Check prerequisites
    (asserts! (is-eq (get proposer proposal) sender) ERR-NOT-AUTHORIZED)
    (asserts! (get contains-sensitive-info proposal) ERR-INVALID-STATE-TRANSITION)
    (asserts! (not (is-some (index-of current-viewers viewer))) ERR-ALREADY-SPONSORED)
    
    ;; Add to authorized viewers
    (map-set proposal-authorized-viewers 
      proposal-id
      (append current-viewers viewer)
    )
    
    (ok true)
  )
)

;; Revoke authorization to view sensitive information
(define-public (revoke-authorization (proposal-id uint) (viewer principal))
  (let (
    (proposal (unwrap! (map-get? proposals proposal-id) ERR-INVALID-PROPOSAL-ID))
    (sender tx-sender)
    (current-viewers (default-to (list) (map-get? proposal-authorized-viewers proposal-id)))
    (viewer-index (index-of current-viewers viewer))
  )
    ;; Check prerequisites
    (asserts! (is-eq (get proposer proposal) sender) ERR-NOT-AUTHORIZED)
    (asserts! (is-some viewer-index) ERR-SENSITIVE-INFO-ACCESS)
    
    ;; Remove from authorized viewers - we must create a new list excluding the viewer
    (map-set proposal-authorized-viewers 
      proposal-id
      (filter (compose not (lambda (p) (is-eq p viewer))) current-viewers)
    )
    
    (ok true)
  )
)

;; Mark a proposal as passed (this would typically be called by a voting contract)
;; Note: In a real implementation, this would likely be restricted to the voting contract
(define-public (mark-proposal-passed (proposal-id uint))
  (let (
    (proposal (unwrap! (map-get? proposals proposal-id) ERR-INVALID-PROPOSAL-ID))
  )
    ;; Typically would check authorization from a voting contract
    ;; For demo purposes, allowing tx-sender but would be restricted in production
    
    ;; Check prerequisites
    (asserts! (is-eq (get status proposal) STATUS-ACTIVE) ERR-PROPOSAL-NOT-ACTIVE)
    
    ;; Update the proposal
    (update-proposal-status proposal-id STATUS-PASSED)
  )
)

;; Mark a proposal as rejected (this would typically be called by a voting contract)
(define-public (mark-proposal-rejected (proposal-id uint))
  (let (
    (proposal (unwrap! (map-get? proposals proposal-id) ERR-INVALID-PROPOSAL-ID))
  )
    ;; Typically would check authorization from a voting contract
    ;; For demo purposes, allowing tx-sender but would be restricted in production
    
    ;; Check prerequisites
    (asserts! (is-eq (get status proposal) STATUS-ACTIVE) ERR-PROPOSAL-NOT-ACTIVE)
    
    ;; Update the proposal
    (update-proposal-status proposal-id STATUS-REJECTED)
  )
)