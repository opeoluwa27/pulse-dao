;; membership-registry
;;
;; This contract manages the membership lifecycle for a healthcare cooperative DAO.
;; It handles membership applications, verification, role assignment, renewals, and terminations
;; while maintaining a secure registry of all members and their associated roles and permissions.
;; The contract serves as the foundation for the governance structure of the PulseDAO,
;; enabling different stakeholder types to participate in decision-making.
;; Error constants
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-NOT-ADMIN (err u101))
(define-constant ERR-ALREADY-MEMBER (err u102))
(define-constant ERR-NOT-MEMBER (err u103))
(define-constant ERR-APPLICATION-NOT-FOUND (err u104))
(define-constant ERR-INVALID-ROLE (err u105))
(define-constant ERR-INVALID-STATUS (err u106))
(define-constant ERR-MEMBERSHIP-EXPIRED (err u107))
(define-constant ERR-ALREADY-APPLIED (err u108))
(define-constant ERR-SELF-VERIFICATION (err u109))
;; Constants
(define-constant ROLE-PATIENT u1)
(define-constant ROLE-PROVIDER u2)
(define-constant ROLE-ADMIN u3)
(define-constant STATUS-PENDING u1)
(define-constant STATUS-ACTIVE u2)
(define-constant STATUS-INACTIVE u3)
(define-constant STATUS-REJECTED u4)
;; Data maps and variables
;; Membership data for each address
(define-map memberships
  { address: principal }
  {
    role: uint,
    status: uint,
    joined-at: uint,
    expires-at: uint,
    verified-by: (optional principal),
  }
)
;; Pending applications
(define-map applications
  { applicant: principal }
  {
    role: uint,
    applied-at: uint,
    credentials: (string-utf8 256),
  }
)
;; Variable to track the membership count
(define-data-var member-count uint u0)
;; Contract owner with super-admin privileges
(define-data-var contract-owner principal tx-sender)
;; Data map to track role-based voting power
(define-map role-weights
  { role: uint }
  { weight: uint }
)
;; Initialize role weights
(map-set role-weights { role: ROLE-PATIENT } { weight: u1 }) (map-set role-weights { role: ROLE-PROVIDER } { weight: u2 }) (map-set role-weights { role: ROLE-ADMIN } { weight: u3 }) ;; Private functions
;; Check if the caller is an admin or contract owner
(define-private (is-authorized-admin)
  (let ((caller-info (default-to {
      role: u0,
      status: u0,
      joined-at: u0,
      expires-at: u0,
      verified-by: none,
    }
      (map-get? memberships { address: tx-sender })
    )))
    (or
      (is-eq tx-sender (var-get contract-owner))
      (and
        (is-eq (get role caller-info) ROLE-ADMIN)
        (is-eq (get status caller-info) STATUS-ACTIVE)
      )
    )
  )
)

;; Check if a membership is valid and active
(define-private (is-active-member (address principal))
  (let ((member-info (default-to {
      role: u0,
      status: u0,
      joined-at: u0,
      expires-at: u0,
      verified-by: none,
    }
      (map-get? memberships { address: address })
    )))
    (and
      (is-eq (get status member-info) STATUS-ACTIVE)
      (> (get expires-at member-info) block-height)
    )
  )
)

;; Check if a role value is valid
(define-private (is-valid-role (role uint))
  (or
    (is-eq role ROLE-PATIENT)
    (is-eq role ROLE-PROVIDER)
    (is-eq role ROLE-ADMIN)
  )
)

;; Check if a status value is valid
(define-private (is-valid-status (status uint))
  (or
    (is-eq status STATUS-PENDING)
    (is-eq status STATUS-ACTIVE)
    (is-eq status STATUS-INACTIVE)
    (is-eq status STATUS-REJECTED)
  )
)

;; Increment member count
(define-private (increment-member-count)
  (var-set member-count (+ (var-get member-count) u1))
)

;; Decrement member count
(define-private (decrement-member-count)
  (var-set member-count (- (var-get member-count) u1))
)

;; Read-only functions
;; Get the current member count
(define-read-only (get-member-count)
  (var-get member-count)
)

;; Check if an address is a member
(define-read-only (is-member (address principal))
  (is-active-member address)
)

;; Get member information
(define-read-only (get-member-info (address principal))
  (map-get? memberships { address: address })
)

;; Get application status
(define-read-only (get-application (applicant principal))
  (map-get? applications { applicant: applicant })
)

;; Get voting weight for a specific role
(define-read-only (get-role-weight (role uint))
  (default-to { weight: u0 } (map-get? role-weights { role: role }))
)

;; Get voting weight for a specific member
(define-read-only (get-member-weight (address principal))
  (let ((member-info (default-to {
      role: u0,
      status: u0,
      joined-at: u0,
      expires-at: u0,
      verified-by: none,
    }
      (map-get? memberships { address: address })
    )))
    (if (is-active-member address)
      (get weight
        (default-to { weight: u0 }
          (map-get? role-weights { role: (get role member-info) })
        ))
      u0
    )
  )
)

;; Public functions
;; Apply for membership
(define-public (apply-for-membership
    (role uint)
    (credentials (string-utf8 256))
  )
  (begin
    ;; Check if role is valid
    (asserts! (is-valid-role role) ERR-INVALID-ROLE)
    ;; Check if already a member
    (asserts! (not (is-member tx-sender)) ERR-ALREADY-MEMBER)
    ;; Check if already applied
    (asserts! (is-none (map-get? applications { applicant: tx-sender }))
      ERR-ALREADY-APPLIED
    )
    ;; Store application
    (map-set applications { applicant: tx-sender } {
      role: role,
      applied-at: block-height,
      credentials: credentials,
    })
    (ok true)
  )
)

;; Approve membership application
(define-public (approve-membership
    (applicant principal)
    (membership-duration uint)
  )
  (let ((application (map-get? applications { applicant: applicant })))
    ;; Check admin authorization
    (asserts! (is-authorized-admin) ERR-NOT-ADMIN)
    ;; Check if application exists
    (asserts! (is-some application) ERR-APPLICATION-NOT-FOUND)
    ;; Verify not approving self (prevent circumventing verification)
    (asserts! (not (is-eq tx-sender applicant)) ERR-SELF-VERIFICATION)
    ;; Unwrap application data
    (let ((app (unwrap-panic application)))
      ;; Delete application
      (map-delete applications { applicant: applicant })
      ;; Create membership
      (map-set memberships { address: applicant } {
        role: (get role app),
        status: STATUS-ACTIVE,
        joined-at: block-height,
        expires-at: (+ block-height membership-duration),
        verified-by: (some tx-sender),
      })
      ;; Increment member count
      (increment-member-count)
      (ok true)
    )
  )
)

;; Reject membership application
(define-public (reject-membership (applicant principal))
  (begin
    ;; Check admin authorization
    (asserts! (is-authorized-admin) ERR-NOT-ADMIN)
    ;; Check if application exists
    (asserts! (is-some (map-get? applications { applicant: applicant }))
      ERR-APPLICATION-NOT-FOUND
    )
    ;; Delete application
    (map-delete applications { applicant: applicant })
    (ok true)
  )
)

;; Renew membership
(define-public (renew-membership
    (address principal)
    (extension-period uint)
  )
  (let ((member-info (map-get? memberships { address: address })))
    ;; Check admin authorization
    (asserts! (is-authorized-admin) ERR-NOT-ADMIN)
    ;; Check if member exists
    (asserts! (is-some member-info) ERR-NOT-MEMBER)
    (let ((info (unwrap-panic member-info)))
      ;; Update membership expiration
      (map-set memberships { address: address } {
        role: (get role info),
        status: STATUS-ACTIVE,
        joined-at: (get joined-at info),
        expires-at: (+ block-height extension-period),
        verified-by: (get verified-by info),
      })
      (ok true)
    )
  )
)

;; Terminate membership
(define-public (terminate-membership (address principal))
  (let ((member-info (map-get? memberships { address: address })))
    ;; Check admin authorization or self-termination
    (asserts! (or (is-eq tx-sender address) (is-authorized-admin))
      ERR-NOT-AUTHORIZED
    )
    ;; Check if member exists
    (asserts! (is-some member-info) ERR-NOT-MEMBER)
    (let ((info (unwrap-panic member-info)))
      ;; Update membership to inactive
      (map-set memberships { address: address } {
        role: (get role info),
        status: STATUS-INACTIVE,
        joined-at: (get joined-at info),
        expires-at: (get expires-at info),
        verified-by: (get verified-by info),
      })
      ;; Decrement member count
      (decrement-member-count)
      (ok true)
    )
  )
)

;; Update member role
(define-public (update-member-role
    (address principal)
    (new-role uint)
  )
  (let ((member-info (map-get? memberships { address: address })))
    ;; Check admin authorization
    (asserts! (is-authorized-admin) ERR-NOT-ADMIN)
    ;; Check if role is valid
    (asserts! (is-valid-role new-role) ERR-INVALID-ROLE)
    ;; Check if member exists
    (asserts! (is-some member-info) ERR-NOT-MEMBER)
    (let ((info (unwrap-panic member-info)))
      ;; Update membership role
      (map-set memberships { address: address } {
        role: new-role,
        status: (get status info),
        joined-at: (get joined-at info),
        expires-at: (get expires-at info),
        verified-by: (get verified-by info),
      })
      (ok true)
    )
  )
)

;; Update role voting weight
(define-public (update-role-weight
    (role uint)
    (weight uint)
  )
  (begin
    ;; Check admin authorization
    (asserts! (is-authorized-admin) ERR-NOT-ADMIN)
    ;; Check if role is valid
    (asserts! (is-valid-role role) ERR-INVALID-ROLE)
    ;; Update role weight
    (map-set role-weights { role: role } { weight: weight })
    (ok true)
  )
)

;; Transfer contract ownership
(define-public (transfer-ownership (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
    (var-set contract-owner new-owner)
    (ok true)
  )
)
