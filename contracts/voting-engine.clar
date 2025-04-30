;; voting-engine
;; A democratic voting system tailored for healthcare cooperative decision-making
;; that supports various voting mechanisms, healthcare-specific privacy considerations,
;; and delegation capabilities while ensuring secure and auditable voting outcomes.

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-PROPOSAL-NOT-FOUND (err u101))
(define-constant ERR-PROPOSAL-EXPIRED (err u102))
(define-constant ERR-PROPOSAL-NOT-ACTIVE (err u103))
(define-constant ERR-ALREADY-VOTED (err u104))
(define-constant ERR-INVALID-VOTE (err u105))
(define-constant ERR-INVALID-VOTING-POWER (err u106))
(define-constant ERR-QUORUM-NOT-MET (err u107))
(define-constant ERR-INVALID-DELEGATE (err u108))
(define-constant ERR-DELEGATION-CYCLE (err u109))
(define-constant ERR-INVALID-VOTING-MECHANISM (err u110))
(define-constant ERR-NOT-MEMBER (err u111))
(define-constant ERR-PROPOSAL-ALREADY-EXISTS (err u112))

;; Voting mechanism types
(define-constant VOTING-MECHANISM-SIMPLE-MAJORITY u1)
(define-constant VOTING-MECHANISM-QUADRATIC u2)
(define-constant VOTING-MECHANISM-ROLE-WEIGHTED u3)

;; Vote options
(define-constant VOTE-FOR u1)
(define-constant VOTE-AGAINST u2)
(define-constant VOTE-ABSTAIN u3)

;; Privacy level indicators
(define-constant PRIVACY-PUBLIC u1)
(define-constant PRIVACY-PRIVATE u2)  ;; For sensitive healthcare decisions

;; Data structures
(define-map proposals
  {proposal-id: uint}
  {
    title: (string-ascii 100),
    description: (string-utf8 1000),
    creator: principal,
    voting-mechanism: uint,
    privacy-level: uint,
    start-block-height: uint,
    end-block-height: uint,
    quorum-requirement: uint,
    status: uint,  ;; 1: active, 2: passed, 3: failed, 4: expired
    role-weights: (optional (list 10 {role: uint, weight: uint})),
    votes-for: uint,
    votes-against: uint,
    votes-abstain: uint,
    total-voting-power-used: uint
  }
)

;; Tracks individual votes
(define-map votes
  {proposal-id: uint, voter: principal}
  {
    vote-direction: uint,
    voting-power-used: uint,
    timestamp: uint
  }
)

;; Tracks membership roles for role-weighted voting
(define-map member-roles
  {member: principal}
  {roles: (list 5 uint)}
)

;; Delegation system
(define-map delegations
  {delegator: principal}
  {delegate: principal}
)

;; Tracks voting power for quadratic voting
(define-map voting-power
  {member: principal}
  {power: uint}
)

;; Counter for proposal IDs
(define-data-var next-proposal-id uint u1)

;; Admin principal for governance system
(define-data-var dao-admin principal tx-sender)

;; Helper functions

;; Checks if a principal is a member of the cooperative
(define-private (is-member (user principal))
  (default-to false (map-get? member-roles {member: user}))
)

;; Calculates a member's voting power based on the specified mechanism
(define-private (calculate-voting-power (member principal) (proposal-id uint))
  (let ((proposal (unwrap! (map-get? proposals {proposal-id: proposal-id}) u0))
        (mechanism (get voting-mechanism proposal)))
    (cond
      ;; Simple majority - 1 vote per member
      ((is-eq mechanism VOTING-MECHANISM-SIMPLE-MAJORITY) u1)
      
      ;; Quadratic voting - square root of allocated power
      ((is-eq mechanism VOTING-MECHANISM-QUADRATIC)
        (let ((power (default-to {power: u0} (map-get? voting-power {member: member}))))
          (sqrti (get power power))))
      
      ;; Role-weighted voting - based on member's assigned roles
      ((is-eq mechanism VOTING-MECHANISM-ROLE-WEIGHTED)
        (let ((member-role-list (default-to {roles: (list)} (map-get? member-roles {member: member})))
              (weights (default-to (list) (get role-weights proposal))))
          (fold + 
               (map 
                 (lambda (role)
                   (default-to u1 
                     (get weight 
                       (find (lambda (weight-item) (is-eq (get role weight-item) role)) weights))))
                 (get roles member-role-list))
               u0)))
      
      ;; Default case
      u0)
  )
)

;; Resolves a delegated vote - follows chain of delegation to find the final delegate
(define-private (resolve-delegate (member principal) (visited-list (list 50 principal)))
  (let ((delegation (map-get? delegations {delegator: member})))
    (if (or (is-none delegation) 
            (> (len visited-list) u49) 
            (is-some (index-of visited-list (get delegate (default-to {delegate: member} delegation)))))
        member
        (resolve-delegate (get delegate (unwrap-panic delegation)) (append visited-list member)))
  )
)

;; Checks if a proposal has met the quorum requirement
(define-private (check-quorum (proposal-id uint))
  (let ((proposal (unwrap-panic (map-get? proposals {proposal-id: proposal-id}))))
    (>= (+ (get votes-for proposal) (get votes-against proposal) (get votes-abstain proposal))
        (get quorum-requirement proposal))
  )
)

;; Checks if a proposal has reached its end block height
(define-private (is-proposal-expired (proposal-id uint))
  (let ((proposal (unwrap-panic (map-get? proposals {proposal-id: proposal-id}))))
    (>= block-height (get end-block-height proposal))
  )
)

;; Calculates the result of a proposal
(define-private (calculate-proposal-result (proposal-id uint))
  (let ((proposal (unwrap-panic (map-get? proposals {proposal-id: proposal-id}))))
    (if (not (check-quorum proposal-id))
        (map-set proposals 
                {proposal-id: proposal-id} 
                (merge proposal {status: u3}))  ;; Failed due to quorum not met
        (if (> (get votes-for proposal) (get votes-against proposal))
            (map-set proposals 
                    {proposal-id: proposal-id} 
                    (merge proposal {status: u2}))  ;; Passed
            (map-set proposals 
                    {proposal-id: proposal-id} 
                    (merge proposal {status: u3}))))  ;; Failed
  )
)

;; Read-only functions

;; Get proposal details
(define-read-only (get-proposal (proposal-id uint))
  (map-get? proposals {proposal-id: proposal-id})
)

;; Get a member's vote on a specific proposal
(define-read-only (get-vote (proposal-id uint) (voter principal))
  (map-get? votes {proposal-id: proposal-id, voter: voter})
)

;; Get delegated voter for a member
(define-read-only (get-delegation (delegator principal))
  (map-get? delegations {delegator: delegator})
)

;; Get member's roles
(define-read-only (get-member-roles (member principal))
  (map-get? member-roles {member: member})
)

;; Check if a proposal is active
(define-read-only (is-proposal-active (proposal-id uint))
  (let ((proposal (unwrap-panic (map-get? proposals {proposal-id: proposal-id}))))
    (and 
      (is-eq (get status proposal) u1)
      (>= block-height (get start-block-height proposal))
      (< block-height (get end-block-height proposal))
    )
  )
)

;; Public functions

;; Creates a new proposal
(define-public (create-proposal 
  (title (string-ascii 100)) 
  (description (string-utf8 1000))
  (voting-mechanism uint)
  (privacy-level uint)
  (duration uint)
  (quorum-requirement uint)
  (role-weights (optional (list 10 {role: uint, weight: uint})))
)
  (let ((proposal-id (var-get next-proposal-id)))
    ;; Check authorization
    (asserts! (is-member tx-sender) ERR-NOT-MEMBER)
    
    ;; Validate inputs
    (asserts! (or (is-eq voting-mechanism VOTING-MECHANISM-SIMPLE-MAJORITY)
                 (is-eq voting-mechanism VOTING-MECHANISM-QUADRATIC)
                 (is-eq voting-mechanism VOTING-MECHANISM-ROLE-WEIGHTED))
             ERR-INVALID-VOTING-MECHANISM)
    
    ;; Create the proposal
    (map-set proposals
      {proposal-id: proposal-id}
      {
        title: title,
        description: description,
        creator: tx-sender,
        voting-mechanism: voting-mechanism,
        privacy-level: privacy-level,
        start-block-height: block-height,
        end-block-height: (+ block-height duration),
        quorum-requirement: quorum-requirement,
        status: u1,  ;; Active
        role-weights: role-weights,
        votes-for: u0,
        votes-against: u0,
        votes-abstain: u0,
        total-voting-power-used: u0
      }
    )
    
    ;; Increment proposal ID counter
    (var-set next-proposal-id (+ proposal-id u1))
    
    (ok proposal-id)
  )
)

;; Cast a vote on a proposal
(define-public (cast-vote (proposal-id uint) (vote-direction uint))
  (let ((proposal (unwrap! (map-get? proposals {proposal-id: proposal-id}) ERR-PROPOSAL-NOT-FOUND))
        (effective-voter (resolve-delegate tx-sender (list tx-sender))))
    
    ;; Check if user is a member
    (asserts! (is-member tx-sender) ERR-NOT-MEMBER)
    
    ;; Check if proposal is active
    (asserts! (is-proposal-active proposal-id) ERR-PROPOSAL-NOT-ACTIVE)
    
    ;; Check if already voted
    (asserts! (is-none (map-get? votes {proposal-id: proposal-id, voter: effective-voter})) ERR-ALREADY-VOTED)
    
    ;; Check if vote direction is valid
    (asserts! (or (is-eq vote-direction VOTE-FOR) 
                 (is-eq vote-direction VOTE-AGAINST) 
                 (is-eq vote-direction VOTE-ABSTAIN))
             ERR-INVALID-VOTE)
    
    ;; Calculate voting power
    (let ((voting-power (calculate-voting-power effective-voter proposal-id)))
      
      ;; Validate voting power
      (asserts! (> voting-power u0) ERR-INVALID-VOTING-POWER)
      
      ;; Record the vote
      (map-set votes
        {proposal-id: proposal-id, voter: effective-voter}
        {
          vote-direction: vote-direction,
          voting-power-used: voting-power,
          timestamp: block-height
        }
      )
      
      ;; Update proposal vote counts
      (match vote-direction
        VOTE-FOR (map-set proposals 
                  {proposal-id: proposal-id}
                  (merge proposal 
                    {
                      votes-for: (+ (get votes-for proposal) voting-power),
                      total-voting-power-used: (+ (get total-voting-power-used proposal) voting-power)
                    }))
        VOTE-AGAINST (map-set proposals 
                      {proposal-id: proposal-id}
                      (merge proposal 
                        {
                          votes-against: (+ (get votes-against proposal) voting-power),
                          total-voting-power-used: (+ (get total-voting-power-used proposal) voting-power)
                        }))
        VOTE-ABSTAIN (map-set proposals 
                      {proposal-id: proposal-id}
                      (merge proposal 
                        {
                          votes-abstain: (+ (get votes-abstain proposal) voting-power),
                          total-voting-power-used: (+ (get total-voting-power-used proposal) voting-power)
                        }))
        ERR-INVALID-VOTE
      )
      
      (ok true)
    )
  )
)

;; Finalize a proposal after voting period ends
(define-public (finalize-proposal (proposal-id uint))
  (let ((proposal (unwrap! (map-get? proposals {proposal-id: proposal-id}) ERR-PROPOSAL-NOT-FOUND)))
    ;; Check if proposal has ended
    (asserts! (is-proposal-expired proposal-id) ERR-PROPOSAL-NOT-EXPIRED)
    
    ;; Check if proposal is still active (not already finalized)
    (asserts! (is-eq (get status proposal) u1) ERR-PROPOSAL-NOT-ACTIVE)
    
    ;; Calculate result
    (calculate-proposal-result proposal-id)
    
    (ok true)
  )
)

;; Set up delegation
(define-public (delegate-vote (delegate-to principal))
  ;; Check if user is a member
  (asserts! (is-member tx-sender) ERR-NOT-MEMBER)
  
  ;; Check if delegate is a member
  (asserts! (is-member delegate-to) ERR-NOT-MEMBER)
  
  ;; Prevent self-delegation
  (asserts! (not (is-eq tx-sender delegate-to)) ERR-INVALID-DELEGATE)
  
  ;; Check for delegation cycles
  (let ((current-delegate delegate-to)
        (visited-list (list tx-sender)))
    (while (and 
            (is-some (map-get? delegations {delegator: current-delegate}))
            (< (len visited-list) u50))
      (begin
        (asserts! (not (is-eq (unwrap-panic (get delegate (map-get? delegations {delegator: current-delegate}))) tx-sender))
                 ERR-DELEGATION-CYCLE)
        (set visited-list (append visited-list current-delegate))
        (set current-delegate (unwrap-panic (get delegate (map-get? delegations {delegator: current-delegate}))))
      )
    )
  )
  
  ;; Set delegation
  (map-set delegations
    {delegator: tx-sender}
    {delegate: delegate-to}
  )
  
  (ok true)
)

;; Remove delegation
(define-public (remove-delegation)
  (begin
    (map-delete delegations {delegator: tx-sender})
    (ok true)
  )
)

;; Admin function to register a new member
(define-public (register-member (new-member principal) (roles (list 5 uint)) (initial-voting-power uint))
  (begin
    ;; Ensure only admin can register members
    (asserts! (is-eq tx-sender (var-get dao-admin)) ERR-NOT-AUTHORIZED)
    
    ;; Add member roles
    (map-set member-roles
      {member: new-member}
      {roles: roles}
    )
    
    ;; Set initial voting power for quadratic voting
    (map-set voting-power
      {member: new-member}
      {power: initial-voting-power}
    )
    
    (ok true)
  )
)

;; Admin function to update a member's roles
(define-public (update-member-roles (member principal) (roles (list 5 uint)))
  (begin
    ;; Ensure only admin can update roles
    (asserts! (is-eq tx-sender (var-get dao-admin)) ERR-NOT-AUTHORIZED)
    
    ;; Update member roles
    (map-set member-roles
      {member: member}
      {roles: roles}
    )
    
    (ok true)
  )
)

;; Admin function to update member's voting power (for quadratic voting)
(define-public (update-voting-power (member principal) (power uint))
  (begin
    ;; Ensure only admin can update voting power
    (asserts! (is-eq tx-sender (var-get dao-admin)) ERR-NOT-AUTHORIZED)
    
    ;; Update voting power
    (map-set voting-power
      {member: member}
      {power: power}
    )
    
    (ok true)
  )
)

;; Transfer DAO admin role to a new principal
(define-public (transfer-admin (new-admin principal))
  (begin
    ;; Ensure only current admin can transfer role
    (asserts! (is-eq tx-sender (var-get dao-admin)) ERR-NOT-AUTHORIZED)
    
    ;; Update admin
    (var-set dao-admin new-admin)
    
    (ok true)
  )
)