;; Minimal Verifiable Credential System
;; W3C-compatible credential issuance and verification

;; Error constants
(define-constant ERR-NOT-FOUND u404)
(define-constant ERR-UNAUTHORIZED u401)
(define-constant ERR-INVALID-PARAMS u400)
(define-constant ERR-ALREADY-EXISTS u409)
(define-constant ERR-EXPIRED u410)
(define-constant ERR-REVOKED u411)
(define-constant ERR-INACTIVE u412)

;; Data structures
(define-map issuers
  { id: (string-ascii 64) }
  {
    name: (string-utf8 64),
    controller: principal,
    active: bool,
    created-at: uint
  }
)

(define-map schemas
  { id: (string-ascii 64) }
  {
    name: (string-utf8 64),
    issuer: (string-ascii 64),
    attributes: (list 10 (string-ascii 32)),
    created-at: uint
  }
)

(define-map credentials
  { id: (string-ascii 64) }
  {
    subject: (string-ascii 64),
    issuer: (string-ascii 64),
    schema: (string-ascii 64),
    hash: (buff 32),
    issued-at: uint,
    expires-at: (optional uint),
    status: (string-ascii 16)
  }
)

(define-map subjects
  { id: (string-ascii 64) }
  {
    controller: principal,
    credential-count: uint,
    created-at: uint
  }
)

(define-map verifications
  { id: uint }
  {
    verifier: principal,
    credential: (string-ascii 64),
    timestamp: uint,
    success: bool
  }
)

;; Counters
(define-data-var verification-counter uint u0)

;; Core functions

;; Register issuer
(define-public (register-issuer (id (string-ascii 64)) (name (string-utf8 64)))
  (begin
    ;; Validate inputs
    (asserts! (and (> (len id) u7) (< (len id) u65)) (err ERR-INVALID-PARAMS))
    (asserts! (and (> (len name) u0) (< (len name) u65)) (err ERR-INVALID-PARAMS))
    (asserts! (is-none (map-get? issuers { id: id })) (err ERR-ALREADY-EXISTS))
    
    ;; Create issuer
    (map-set issuers
      { id: id }
      {
        name: name,
        controller: tx-sender,
        active: true,
        created-at: block-height
      }
    )
    (ok id)
  )
)

;; Create schema
(define-public (create-schema 
                (id (string-ascii 64))
                (name (string-utf8 64))
                (issuer-id (string-ascii 64))
                (attributes (list 10 (string-ascii 32))))
  (let ((issuer (unwrap! (map-get? issuers { id: issuer-id }) (err ERR-NOT-FOUND))))
    ;; Validate
    (asserts! (is-eq tx-sender (get controller issuer)) (err ERR-UNAUTHORIZED))
    (asserts! (get active issuer) (err ERR-INACTIVE))
    (asserts! (> (len attributes) u0) (err ERR-INVALID-PARAMS))
    (asserts! (is-none (map-get? schemas { id: id })) (err ERR-ALREADY-EXISTS))
    
    ;; Create schema
    (map-set schemas
      { id: id }
      {
        name: name,
        issuer: issuer-id,
        attributes: attributes,
        created-at: block-height
      }
    )
    (ok id)
  )
)

;; Register subject
(define-public (register-subject (id (string-ascii 64)))
  (begin
    ;; Validate
    (asserts! (and (> (len id) u7) (< (len id) u65)) (err ERR-INVALID-PARAMS))
    (asserts! (is-none (map-get? subjects { id: id })) (err ERR-ALREADY-EXISTS))
    
    ;; Create subject
    (map-set subjects
      { id: id }
      {
        controller: tx-sender,
        credential-count: u0,
        created-at: block-height
      }
    )
    (ok id)
  )
)

;; Issue credential
(define-public (issue-credential
                (id (string-ascii 64))
                (subject-id (string-ascii 64))
                (issuer-id (string-ascii 64))
                (schema-id (string-ascii 64))
                (credential-hash (buff 32))
                (expires-at (optional uint)))
  (let 
    ((issuer (unwrap! (map-get? issuers { id: issuer-id }) (err ERR-NOT-FOUND)))
     (schema (unwrap! (map-get? schemas { id: schema-id }) (err ERR-NOT-FOUND)))
     (subject (unwrap! (map-get? subjects { id: subject-id }) (err ERR-NOT-FOUND))))
    
    ;; Validate
    (asserts! (is-eq tx-sender (get controller issuer)) (err ERR-UNAUTHORIZED))
    (asserts! (get active issuer) (err ERR-INACTIVE))
    (asserts! (is-eq (get issuer schema) issuer-id) (err ERR-UNAUTHORIZED))
    (asserts! (is-eq (len credential-hash) u32) (err ERR-INVALID-PARAMS))
    (asserts! (is-none (map-get? credentials { id: id })) (err ERR-ALREADY-EXISTS))
    
    ;; Validate expiration
    (match expires-at
      exp-time (asserts! (> exp-time block-height) (err ERR-INVALID-PARAMS))
      true)
    
    ;; Issue credential
    (map-set credentials
      { id: id }
      {
        subject: subject-id,
        issuer: issuer-id,
        schema: schema-id,
        hash: credential-hash,
        issued-at: block-height,
        expires-at: expires-at,
        status: "active"
      }
    )
    
    ;; Update subject count
    (map-set subjects
      { id: subject-id }
      (merge subject { credential-count: (+ (get credential-count subject) u1) })
    )
    
    (ok id)
  )
)

;; Revoke credential
(define-public (revoke-credential (id (string-ascii 64)))
  (let 
    ((credential (unwrap! (map-get? credentials { id: id }) (err ERR-NOT-FOUND)))
     (issuer (unwrap! (map-get? issuers { id: (get issuer credential) }) (err ERR-NOT-FOUND))))
    
    ;; Validate
    (asserts! (is-eq tx-sender (get controller issuer)) (err ERR-UNAUTHORIZED))
    (asserts! (is-eq (get status credential) "active") (err ERR-INVALID-PARAMS))
    
    ;; Revoke
    (map-set credentials
      { id: id }
      (merge credential { status: "revoked" })
    )
    (ok true)
  )
)

;; Verify credential
(define-public (verify-credential (id (string-ascii 64)) (proof (buff 64)))
  (let 
    ((credential (unwrap! (map-get? credentials { id: id }) (err ERR-NOT-FOUND)))
     (issuer (unwrap! (map-get? issuers { id: (get issuer credential) }) (err ERR-NOT-FOUND)))
     (verification-id (var-get verification-counter)))
    
    ;; Validate credential status
    (asserts! (is-eq (get status credential) "active") (err ERR-REVOKED))
    (asserts! (get active issuer) (err ERR-INACTIVE))
    (asserts! (is-eq (len proof) u64) (err ERR-INVALID-PARAMS))
    
    ;; Check expiration
    (match (get expires-at credential)
      exp-time (asserts! (< block-height exp-time) (err ERR-EXPIRED))
      true)
    
    ;; Record verification
    (map-set verifications
      { id: verification-id }
      {
        verifier: tx-sender,
        credential: id,
        timestamp: block-height,
        success: true
      }
    )
    
    ;; Increment counter
    (var-set verification-counter (+ verification-id u1))
    (ok verification-id)
  )
)

;; Deactivate issuer
(define-public (deactivate-issuer (id (string-ascii 64)))
  (let ((issuer (unwrap! (map-get? issuers { id: id }) (err ERR-NOT-FOUND))))
    ;; Validate
    (asserts! (is-eq tx-sender (get controller issuer)) (err ERR-UNAUTHORIZED))
    (asserts! (get active issuer) (err ERR-INVALID-PARAMS))
    
    ;; Deactivate
    (map-set issuers { id: id } (merge issuer { active: false }))
    (ok true)
  )
)

;; Read-only functions

(define-read-only (get-issuer (id (string-ascii 64)))
  (ok (unwrap! (map-get? issuers { id: id }) (err ERR-NOT-FOUND)))
)

(define-read-only (get-schema (id (string-ascii 64)))
  (ok (unwrap! (map-get? schemas { id: id }) (err ERR-NOT-FOUND)))
)

(define-read-only (get-credential (id (string-ascii 64)))
  (ok (unwrap! (map-get? credentials { id: id }) (err ERR-NOT-FOUND)))
)

(define-read-only (get-subject (id (string-ascii 64)))
  (ok (unwrap! (map-get? subjects { id: id }) (err ERR-NOT-FOUND)))
)

(define-read-only (get-verification (id uint))
  (ok (unwrap! (map-get? verifications { id: id }) (err ERR-NOT-FOUND)))
)

(define-read-only (check-credential-status (id (string-ascii 64)))
  (let ((credential (unwrap! (map-get? credentials { id: id }) (err ERR-NOT-FOUND))))
    (if (not (is-eq (get status credential) "active"))
        (ok (get status credential))
        (match (get expires-at credential)
          exp-time (if (>= block-height exp-time) (ok "expired") (ok "active"))
          (ok "active")))
  )
)

(define-read-only (is-issuer-active (id (string-ascii 64)))
  (let ((issuer (unwrap! (map-get? issuers { id: id }) (err ERR-NOT-FOUND))))
    (ok (get active issuer))
  )
)

(define-read-only (credential-belongs-to-subject (cred-id (string-ascii 64)) (subj-id (string-ascii 64)))
  (let ((credential (unwrap! (map-get? credentials { id: cred-id }) (err ERR-NOT-FOUND))))
    (ok (is-eq (get subject credential) subj-id))
  )
)

(define-read-only (get-subject-credential-count (id (string-ascii 64)))
  (let ((subject (unwrap! (map-get? subjects { id: id }) (err ERR-NOT-FOUND))))
    (ok (get credential-count subject))
  )
)

(define-read-only (validate-issuer-control (issuer-id (string-ascii 64)) (caller principal))
  (let ((issuer (unwrap! (map-get? issuers { id: issuer-id }) (err ERR-NOT-FOUND))))
    (ok (is-eq caller (get controller issuer)))
  )
)

(define-read-only (get-verification-counter)
  (ok (var-get verification-counter))
)

(define-read-only (get-contract-info)
  (ok { version: "1.0.0", name: "Minimal-VC-System" })
)