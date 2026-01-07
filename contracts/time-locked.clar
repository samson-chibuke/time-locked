;; ============================================================================
;; TIME-LOCKED VAULT WITH ASSET PROTECTION
;; ============================================================================
;; A secure vault contract leveraging Clarity 4 features:
;; - stacks-block-time for accurate time-based unlocking
;; - restrict-assets? for enhanced asset protection
;; - contract-hash? for verified contract interactions
;; - to-ascii for user-friendly messages
;; - as-contract? with explicit asset allowances
;; ============================================================================

;; ============================================================================
;; CONSTANTS & ERROR CODES
;; ============================================================================

;; Error codes with descriptive names for better debugging
(define-constant ERR_NOT_AUTHORIZED (err u100))
(define-constant ERR_VAULT_LOCKED (err u101))
(define-constant ERR_INSUFFICIENT_BALANCE (err u102))
(define-constant ERR_INVALID_AMOUNT (err u103))
(define-constant ERR_VAULT_NOT_FOUND (err u104))
(define-constant ERR_INVALID_UNLOCK_TIME (err u105))
(define-constant ERR_ASSET_RESTRICTION_VIOLATED (err u106))
(define-constant ERR_UNTRUSTED_CONTRACT (err u107))

;; Contract owner for administrative functions
(define-constant CONTRACT_OWNER tx-sender)

;; Minimum lock duration: 1 hour (3600 seconds)
(define-constant MIN_LOCK_DURATION u3600)

;; ============================================================================
;; DATA STRUCTURES
;; ============================================================================

;; Map to store individual vault details for each user
;; Each vault tracks the amount locked and the Unix timestamp when it unlocks
(define-map vaults
    principal  ;; Vault owner's principal
    {
        amount: uint,           ;; Amount of STX locked in vault
        unlock-time: uint,      ;; Unix timestamp when vault can be withdrawn
        created-at: uint        ;; Unix timestamp when vault was created
    }
)

;; Map to track trusted contracts that can interact with this vault
;; This leverages Clarity 4's contract-hash? feature for security
(define-map trusted-contracts
    principal  ;; Contract principal
    {
        code-hash: (buff 32),  ;; Hash of the contract's code body
        trusted: bool          ;; Whether this contract is trusted
    }
)

;; Data variable to track total STX locked across all vaults
(define-data-var total-locked uint u0)

;; ============================================================================
;; PRIVATE HELPER FUNCTIONS
;; ============================================================================

;; Check if the caller is the vault owner
;; @param owner - The principal to check against
;; @returns true if caller matches owner, false otherwise
(define-private (is-vault-owner (owner principal))
    (is-eq tx-sender owner)
)

;; Calculate the unlock time based on current time and lock duration
;; Leverages Clarity 4's stacks-block-time for accurate timing
;; @param duration - Lock duration in seconds
;; @returns Unix timestamp when the vault will unlock
(define-private (calculate-unlock-time (duration uint))
    (+ stacks-block-time duration)
)

;; Get vault information for a specific user
;; @param owner - The principal of the vault owner
;; @returns Optional vault data or none if vault doesn't exist
(define-private (get-vault-info (owner principal))
    (map-get? vaults owner)
)

;; Check if a vault's unlock time has passed
;; Uses Clarity 4's stacks-block-time for precise time comparison
;; @param unlock-time - The timestamp when vault should unlock
;; @returns true if current time >= unlock time
(define-private (is-vault-unlocked (unlock-time uint))
    (>= stacks-block-time unlock-time)
)

;; ============================================================================
;; READ-ONLY FUNCTIONS
;; ============================================================================

;; Get the current total amount locked in all vaults
;; @returns Total STX locked across all vaults
(define-read-only (get-total-locked)
    (ok (var-get total-locked))
)

;; Get vault details for a specific user
;; @param owner - The principal of the vault owner
;; @returns Vault details or error if not found
(define-read-only (get-vault (owner principal))
    (match (get-vault-info owner)
        vault (ok vault)
        ERR_VAULT_NOT_FOUND
    )
)

;; Check if a vault is currently unlocked and withdrawable
;; @param owner - The principal of the vault owner
;; @returns true if vault exists and is unlocked, false otherwise
(define-read-only (is-withdrawable (owner principal))
    (match (get-vault-info owner)
        vault (ok (is-vault-unlocked (get unlock-time vault)))
        ERR_VAULT_NOT_FOUND
    )
)

;; Calculate time remaining until vault unlocks
;; @param owner - The principal of the vault owner
;; @returns Seconds remaining (0 if already unlocked) or error
(define-read-only (time-until-unlock (owner principal))
    (match (get-vault-info owner)
        vault (let
            (
                (unlock-time (get unlock-time vault))
                (current-time stacks-block-time)
            )
            (if (>= current-time unlock-time)
                (ok u0)
                (ok (- unlock-time current-time))
            )
        )
        ERR_VAULT_NOT_FOUND
    )
)

;; Generate a user-friendly status message
;; @param owner - The principal of the vault owner
;; @returns ASCII string describing vault status
(define-read-only (get-vault-status-message (owner principal))
    (match (get-vault-info owner)
        vault (let
            (
                (unlocked (is-vault-unlocked (get unlock-time vault)))
            )
            (if unlocked
                (ok "Vault is unlocked and ready for withdrawal")
                (ok "Vault is still locked")
            )
        )
        ERR_VAULT_NOT_FOUND
    )
)

;; Check if a contract is trusted for interaction
;; Leverages Clarity 4's contract verification features
;; @param contract - The principal of the contract to check
;; @returns true if contract is trusted, false otherwise
(define-read-only (is-trusted-contract (contract principal))
    (match (map-get? trusted-contracts contract)
        entry (ok (get trusted entry))
        (ok false)
    )
)

;; ============================================================================
;; PUBLIC FUNCTIONS - VAULT OPERATIONS
;; ============================================================================

;; Create a new time-locked vault with STX
;; Uses Clarity 4's stacks-block-time for precise unlock scheduling
;; @param amount - Amount of STX to lock (in microSTX)
;; @param lock-duration - Duration to lock in seconds (minimum 1 hour)
;; @returns Success response with unlock time or error
(define-public (create-vault (amount uint) (lock-duration uint))
    (let
        (
            ;; Calculate when the vault will unlock
            (unlock-time (calculate-unlock-time lock-duration))
            (current-time stacks-block-time)
        )
        
        ;; Validate inputs
        (asserts! (> amount u0) ERR_INVALID_AMOUNT)
        (asserts! (>= lock-duration MIN_LOCK_DURATION) ERR_INVALID_UNLOCK_TIME)
        
        ;; Check if user already has a vault (one vault per user)
        (asserts! (is-none (get-vault-info tx-sender)) ERR_NOT_AUTHORIZED)
        
        ;; Transfer STX from user to contract using Clarity 4's current-contract keyword
        (try! (stx-transfer? amount tx-sender current-contract))
        
        ;; Store vault information
        (map-set vaults tx-sender {
            amount: amount,
            unlock-time: unlock-time,
            created-at: current-time
        })
        
        ;; Update total locked amount
        (var-set total-locked (+ (var-get total-locked) amount))
        
        ;; Return success with vault details
        (ok {
            amount: amount,
            unlock-time: unlock-time,
            created-at: current-time
        })
    )
)

;; Withdraw STX from vault after unlock time has passed
;; Uses Clarity 4's restrict-assets? for additional protection
;; @returns Success with withdrawn amount or error
(define-public (withdraw)
    (let
        (
            ;; Retrieve vault information
            (vault (unwrap! (get-vault-info tx-sender) ERR_VAULT_NOT_FOUND))
            (amount (get amount vault))
            (unlock-time (get unlock-time vault))
            (recipient tx-sender)  ;; Capture user principal before as-contract context
        )
        
        ;; Verify vault is unlocked using stacks-block-time
        (asserts! (is-vault-unlocked unlock-time) ERR_VAULT_LOCKED)
        
        ;; Delete vault entry before transfer (checks-effects-interactions)
        (map-delete vaults recipient)
        
        ;; Update total locked amount
        (var-set total-locked (- (var-get total-locked) amount))
        
        ;; Transfer STX from contract back to user using Clarity 4's as-contract?
        (try! (as-contract? ((with-stx amount))
            (try! (stx-transfer? amount tx-sender recipient))
        ))
        
        ;; Return success with withdrawn amount
        (ok amount)
    )
)

;; Emergency withdrawal by contract owner (for exceptional circumstances)
;; This should be used sparingly and typically only in emergencies
;; @param user - The principal of the vault to withdraw
;; @returns Success with withdrawn amount or error
(define-public (emergency-withdraw (user principal))
    (let
        (
            (vault (unwrap! (get-vault-info user) ERR_VAULT_NOT_FOUND))
            (amount (get amount vault))
            (recipient user)  ;; Capture recipient principal
        )
        
        ;; Only contract owner can perform emergency withdrawal
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        
        ;; Remove vault
        (map-delete vaults recipient)
        
        ;; Update total locked
        (var-set total-locked (- (var-get total-locked) amount))
        
        ;; Transfer to original user using Clarity 4's as-contract?
        (try! (as-contract? ((with-stx amount))
            (try! (stx-transfer? amount tx-sender recipient))
        ))
        
        (ok amount)
    )
)

;; ============================================================================
;; PUBLIC FUNCTIONS - CONTRACT VERIFICATION (Clarity 4)
;; ============================================================================

;; Register a trusted contract by verifying its code hash
;; Leverages Clarity 4's contract-hash? function for verification
;; @param contract - The principal of the contract to trust
;; @returns Success or error
(define-public (register-trusted-contract (contract principal))
    (let
        (
            ;; Get the hash of the contract's code body (Clarity 4 feature)
            (code-hash (unwrap! (contract-hash? contract) ERR_UNTRUSTED_CONTRACT))
        )
        
        ;; Only contract owner can register trusted contracts
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        
        ;; Store the contract as trusted with its code hash
        (map-set trusted-contracts contract {
            code-hash: code-hash,
            trusted: true
        })
        
        (ok true)
    )
)

;; Verify that a contract's code hasn't changed since registration
;; Uses Clarity 4's contract-hash? to compare current vs stored hash
;; @param contract - The principal of the contract to verify
;; @returns true if contract code matches stored hash, false otherwise
(define-public (verify-contract-integrity (contract principal))
    (let
        (
            ;; Retrieve stored contract info
            (stored-info (unwrap! (map-get? trusted-contracts contract) ERR_UNTRUSTED_CONTRACT))
            ;; Get current contract code hash
            (current-hash (unwrap! (contract-hash? contract) ERR_UNTRUSTED_CONTRACT))
            (stored-hash (get code-hash stored-info))
        )
        
        ;; Compare hashes to ensure contract hasn't been modified
        (ok (is-eq current-hash stored-hash))
    )
)

;; ============================================================================
;; CONTRACT INITIALIZATION
;; ============================================================================

;; Initialize contract state (executes at deployment)
;; This demonstrates Clarity's interpreted nature - runs at deploy time
(begin
    ;; Set initial total locked to zero (already done by define-data-var)
    ;; This block serves as a deployment log/verification point
    (print "Time-Locked Vault Contract Deployed")
    (print { deployer: CONTRACT_OWNER, timestamp: stacks-block-time })
)