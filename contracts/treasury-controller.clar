;; treasury-controller
;; Governs the health cooperative's financial resources with transparent fund management.
;; This contract manages the cooperative's treasury, handling fund allocations, distributions,
;; expense tracking, and emergency provisions while maintaining a transparent audit trail.
;; Error Codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-AMOUNT (err u101))
(define-constant ERR-INSUFFICIENT-FUNDS (err u102))
(define-constant ERR-PROPOSAL-NOT-FOUND (err u103))
(define-constant ERR-PROPOSAL-NOT-APPROVED (err u104))
(define-constant ERR-EXPENSE-NOT-FOUND (err u105))
(define-constant ERR-EMERGENCY-REQUEST-NOT-FOUND (err u106))
(define-constant ERR-INVALID-PARAMETER (err u107))
(define-constant ERR-EXPENSE-ALREADY-PAID (err u108))
(define-constant ERR-ALREADY-INITIALIZED (err u109))
;; Constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant EMERGENCY-THRESHOLD u3) ;; Minimum approvals needed for emergency funds
;; Data Maps and Variables
;; Track the contract's overall balance
(define-data-var treasury-balance uint u0)
;; Track the emergency fund balance
(define-data-var emergency-fund-balance uint u0)
;; Track governance contract address
(define-data-var governance-contract principal 'ST000000000000000000002AMW42H)
;; Structure for approved proposals that require funding
(define-map approved-proposals
  { proposal-id: uint }
  {
    amount: uint,
    recipient: principal,
    description: (string-ascii 256),
    executed: bool,
    timestamp: uint,
  }
)
;; Track recurring expenses (e.g., practitioner payments, facility maintenance)
(define-map recurring-expenses
  { expense-id: uint }
  {
    recipient: principal,
    amount: uint,
    frequency: uint, ;; Frequency in blocks
    description: (string-ascii 256),
    last-paid-height: uint,
    active: bool,
  }
)
;; Record emergency fund requests
(define-map emergency-requests
  { request-id: uint }
  {
    requester: principal,
    amount: uint,
    description: (string-ascii 256),
    approvals: uint,
    executed: bool,
    approvers: (list 10 principal),
  }
)
;; Financial transaction audit trail
(define-map transaction-history
  { tx-id: uint }
  {
    tx-type: (string-ascii 20),
    amount: uint,
    recipient: principal,
    description: (string-ascii 256),
    timestamp: uint,
  }
)
;; ID counters for various entities
(define-data-var proposal-counter uint u0)
(define-data-var expense-counter uint u0)
(define-data-var emergency-request-counter uint u0)
(define-data-var transaction-counter uint u0)
;; Flag to ensure initialization happens only once
(define-data-var initialized bool false)
;; Private Functions
;; Record a transaction in the audit trail
(define-private (record-transaction
    (tx-type (string-ascii 20))
    (amount uint)
    (recipient principal)
    (description (string-ascii 256))
  )
  (let ((tx-id (var-get transaction-counter)))
    (map-set transaction-history { tx-id: tx-id } {
      tx-type: tx-type,
      amount: amount,
      recipient: recipient,
      description: description,
      timestamp: (unwrap-panic (get-block-info? time u0)),
    })
    (var-set transaction-counter (+ tx-id u1))
    tx-id
  )
)

;; Check if sender is authorized (either contract owner or governance contract)
(define-private (is-authorized)
  (or
    (is-eq tx-sender CONTRACT-OWNER)
    (is-eq tx-sender (var-get governance-contract))
  )
)

;; Transfer funds within the contract
(define-private (transfer-funds
    (amount uint)
    (is-emergency bool)
  )
  (if is-emergency
    (begin
      (asserts! (<= amount (var-get emergency-fund-balance))
        ERR-INSUFFICIENT-FUNDS
      )
      (var-set emergency-fund-balance (- (var-get emergency-fund-balance) amount))
      (ok true)
    )
    (begin
      (asserts!
        (<= amount
          (- (var-get treasury-balance) (var-get emergency-fund-balance))
        )
        ERR-INSUFFICIENT-FUNDS
      )
      (var-set treasury-balance (- (var-get treasury-balance) amount))
      (ok true)
    )
  )
)

;; Public Functions
;; Initialize the treasury controller
(define-public (initialize (governance-addr principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (asserts! (not (var-get initialized)) ERR-ALREADY-INITIALIZED)
    (var-set governance-contract governance-addr)
    (var-set initialized true)
    (ok true)
  )
)

;; Deposit funds into the treasury
(define-public (deposit (amount uint))
  (begin
    (asserts! (> amount u0) ERR-INVALID-AMOUNT)
    (var-set treasury-balance (+ (var-get treasury-balance) amount))
    ;; Record the transaction
    (record-transaction "deposit" amount tx-sender "Treasury deposit")
    (ok true)
  )
)

;; Allocate funds to the emergency fund
(define-public (allocate-to-emergency-fund (amount uint))
  (begin
    (asserts! (is-authorized) ERR-NOT-AUTHORIZED)
    (asserts! (> amount u0) ERR-INVALID-AMOUNT)
    (asserts!
      (<= amount (- (var-get treasury-balance) (var-get emergency-fund-balance)))
      ERR-INSUFFICIENT-FUNDS
    )
    (var-set emergency-fund-balance (+ (var-get emergency-fund-balance) amount))
    ;; Record the transaction
    (record-transaction "emergency-alloc" amount tx-sender
      "Emergency fund allocation"
    )
    (ok true)
  )
)

;; Register an approved proposal for funding
(define-public (register-approved-proposal
    (amount uint)
    (recipient principal)
    (description (string-ascii 256))
  )
  (let ((proposal-id (var-get proposal-counter)))
    (asserts! (is-authorized) ERR-NOT-AUTHORIZED)
    (asserts! (> amount u0) ERR-INVALID-AMOUNT)
    (map-set approved-proposals { proposal-id: proposal-id } {
      amount: amount,
      recipient: recipient,
      description: description,
      executed: false,
      timestamp: (unwrap-panic (get-block-info? time u0)),
    })
    (var-set proposal-counter (+ proposal-id u1))
    (ok proposal-id)
  )
)

;; Register a recurring expense
(define-public (register-recurring-expense
    (recipient principal)
    (amount uint)
    (frequency uint)
    (description (string-ascii 256))
  )
  (let ((expense-id (var-get expense-counter)))
    (asserts! (is-authorized) ERR-NOT-AUTHORIZED)
    (asserts! (and (> amount u0) (> frequency u0)) ERR-INVALID-PARAMETER)
    (map-set recurring-expenses { expense-id: expense-id } {
      recipient: recipient,
      amount: amount,
      frequency: frequency,
      description: description,
      last-paid-height: u0,
      active: true,
    })
    (var-set expense-counter (+ expense-id u1))
    (ok expense-id)
  )
)

;; Deactivate a recurring expense
(define-public (deactivate-recurring-expense (expense-id uint))
  (let ((expense (unwrap! (map-get? recurring-expenses { expense-id: expense-id })
      ERR-EXPENSE-NOT-FOUND
    )))
    (asserts! (is-authorized) ERR-NOT-AUTHORIZED)
    (asserts! (get active expense) ERR-EXPENSE-NOT-FOUND)
    ;; Update expense status
    (map-set recurring-expenses { expense-id: expense-id }
      (merge expense { active: false })
    )
    (ok true)
  )
)

;; Create an emergency fund request
(define-public (create-emergency-request
    (amount uint)
    (description (string-ascii 256))
  )
  (let ((request-id (var-get emergency-request-counter)))
    (asserts! (> amount u0) ERR-INVALID-AMOUNT)
    (asserts! (<= amount (var-get emergency-fund-balance)) ERR-INSUFFICIENT-FUNDS)
    (map-set emergency-requests { request-id: request-id } {
      requester: tx-sender,
      amount: amount,
      description: description,
      approvals: u0,
      executed: false,
      approvers: (list),
    })
    (var-set emergency-request-counter (+ request-id u1))
    (ok request-id)
  )
)

;; Approve an emergency fund request
(define-public (approve-emergency-request (request-id uint))
  (let (
      (request (unwrap! (map-get? emergency-requests { request-id: request-id })
        ERR-EMERGENCY-REQUEST-NOT-FOUND
      ))
      (current-approvers (get approvers request))
    )
    (asserts! (is-authorized) ERR-NOT-AUTHORIZED)
    (asserts! (not (is-some (index-of current-approvers tx-sender)))
      ERR-INVALID-PARAMETER
    )
    ;; Update approvals
    (map-set emergency-requests { request-id: request-id }
      (merge request {
        approvals: (+ (get approvals request) u1),
        approvers: (unwrap-panic (as-max-len? (append current-approvers tx-sender) u10)),
      })
    )
    (ok true)
  )
)

;; Execute an emergency fund request
(define-public (execute-emergency-request (request-id uint))
  (let ((request (unwrap! (map-get? emergency-requests { request-id: request-id })
      ERR-EMERGENCY-REQUEST-NOT-FOUND
    )))
    (asserts! (is-authorized) ERR-NOT-AUTHORIZED)
    (asserts! (>= (get approvals request) EMERGENCY-THRESHOLD) ERR-NOT-AUTHORIZED)
    ;; Transfer funds from emergency fund
    (unwrap! (transfer-funds (get amount request) true) ERR-INSUFFICIENT-FUNDS)
    ;; Update request as executed
    (map-set emergency-requests { request-id: request-id }
      (merge request { executed: true })
    )
    ;; Record the transaction
    (record-transaction "emergency-fund" (get amount request)
      (get requester request) (get description request)
    )
    (ok true)
  )
)

;; Read-Only Functions
;; Get treasury balance
(define-read-only (get-treasury-balance)
  (var-get treasury-balance)
)

;; Get emergency fund balance
(define-read-only (get-emergency-fund-balance)
  (var-get emergency-fund-balance)
)

;; Get proposal details
(define-read-only (get-proposal (proposal-id uint))
  (map-get? approved-proposals { proposal-id: proposal-id })
)

;; Get recurring expense details
(define-read-only (get-recurring-expense (expense-id uint))
  (map-get? recurring-expenses { expense-id: expense-id })
)

;; Get emergency request details
(define-read-only (get-emergency-request (request-id uint))
  (map-get? emergency-requests { request-id: request-id })
)

;; Get transaction details from the audit trail
(define-read-only (get-transaction (tx-id uint))
  (map-get? transaction-history { tx-id: tx-id })
)

;; Get latest ID counters
(define-read-only (get-counters)
  {
    proposal-counter: (var-get proposal-counter),
    expense-counter: (var-get expense-counter),
    emergency-request-counter: (var-get emergency-request-counter),
    transaction-counter: (var-get transaction-counter),
  }
)
