#!/usr/bin/env python3

import argparse
import hashlib
import secrets
import json
import signal
import time
import zlib

from dataclasses import dataclass, asdict
from pathlib import Path




# ============================================================
# BITCOIN MAINNET WIF (separate from JOATT state)
# ============================================================

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    """Encode bytes using the Bitcoin Base58 alphabet."""
    zeros = len(data) - len(data.lstrip(b"\x00"))
    value = int.from_bytes(data, "big")
    encoded = ""
    while value:
        value, rem = divmod(value, 58)
        encoded = BASE58_ALPHABET[rem] + encoded
    return ("1" * zeros) + encoded


def private_key_to_wif(private_key: bytes, compressed: bool = True) -> str:
    """Encode a 32-byte secp256k1 private key as Bitcoin mainnet WIF."""
    if len(private_key) != 32:
        raise ValueError("Private key must be exactly 32 bytes")
    scalar = int.from_bytes(private_key, "big")
    if not 1 <= scalar < SECP256K1_N:
        raise ValueError("Private key scalar is outside the secp256k1 range")
    payload = b"\x80" + private_key + (b"\x01" if compressed else b"")
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58_encode(payload + checksum)


def generate_wif() -> str:
    """Generate a fresh random Bitcoin mainnet WIF locally."""
    scalar = secrets.randbelow(SECP256K1_N - 1) + 1
    return private_key_to_wif(scalar.to_bytes(32, "big"), compressed=True)




def derive_garble_wif(seed: str, salt: str, iterations: int) -> str:
    """Experimental deterministic WIF derivation; not a standard wallet scheme."""
    if not seed:
        raise ValueError("Seed string must not be empty")
    if not salt:
        raise ValueError("Salt must not be empty")
    if iterations < 1:
        raise ValueError("Iterations must be at least 1")

    derived = hashlib.pbkdf2_hmac(
        "sha512",
        seed.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
        dklen=64,
    )
    # Map deterministically into the valid secp256k1 scalar range.
    scalar = (int.from_bytes(derived, "big") % (SECP256K1_N - 1)) + 1
    return private_key_to_wif(scalar.to_bytes(32, "big"), compressed=True)


def prompt_garble_wif() -> None:
    """Prompt locally for a custom seed, salt, and PBKDF2 iteration count."""
    from getpass import getpass

    print("EXPERIMENTAL deterministic CYTHANX Garble-seed -> Bitcoin mainnet WIF")
    print("Not a standard wallet derivation; do not use for funds.")
    seed = getpass("Custom Garble seed string (input hidden): ")
    salt = input("PBKDF2 salt (required; store it to reproduce this key): ").strip()
    raw_iterations = input("PBKDF2-HMAC-SHA-512 iterations (required, e.g. 600000): ").strip()
    try:
        iterations = int(raw_iterations)
        if iterations < 1:
            raise ValueError("Iterations must be at least 1")
        wif = derive_garble_wif(seed, salt, iterations)
    except ValueError as exc:
        raise SystemExit(f"Input error: {exc}") from exc

    print("\\nExperimental WIF (Bitcoin mainnet, compressed-key format):")
    print(wif)
    print("WARNING: deterministic and only as secure as the seed; never share this WIF.")
    print("Record the exact salt and iteration count securely if you need to reproduce it.")


# ============================================================
# GODCHAIN + JOATT CONFIGURATION
# ============================================================

CHAIN_FILE = Path("godchain.json")
STATE_FILE = Path("godchain_joatt_state.json")

NETWORK = "GODCHAIN-TESTNET"
VERSION = "1.0-JOATT"

DIFFICULTY = 4
BLOCK_REWARD = 50
BLOCK_INTERVAL = 10

PBKDF2_ITERATIONS = 2048

RUNNING = True


# ============================================================
# BASIC CRYPTOGRAPHIC FUNCTIONS
# ============================================================

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


# ============================================================
# JOATT TEST DERIVATIVES
# ============================================================

def tiger128_test(data: bytes) -> bytes:
    """
    128-bit TEST-ONLY derivative.

    This is NOT the standardized Tiger hash.
    """

    return sha256(
        b"TIGER128|" +
        b"JOATT|" +
        b"TEST-ONLY|" +
        data
    )[:16]


def haval192_test(data: bytes) -> bytes:
    """
    192-bit TEST-ONLY derivative.

    This is NOT the standardized HAVAL algorithm.
    """

    return sha256(
        b"HAVAL192|" +
        b"JOATT|" +
        b"TEST-ONLY|" +
        data
    )[:24]


# ============================================================
# JOATT TRANSMOGRIFICATION
# ============================================================

def joatt(payload: bytes) -> dict:

    # --------------------------------------------------------
    # 1. Domain separation
    # --------------------------------------------------------

    normalized = (
        NETWORK.encode() +
        b"|" +
        b"JOATT-HAVAL192-TIGER128-TEST-ONLY|" +
        payload
    )

    # --------------------------------------------------------
    # 2. SHA-256 root
    # --------------------------------------------------------

    root = sha256(normalized)

    # --------------------------------------------------------
    # 3. PBKDF2-HMAC-SHA512
    # --------------------------------------------------------

    pbkdf = hashlib.pbkdf2_hmac(
        "sha512",
        root,
        b"JOATT-SALT-TEST-ONLY",
        PBKDF2_ITERATIONS,
        64
    )

    # --------------------------------------------------------
    # 4. Tiger128 test derivative
    # --------------------------------------------------------

    tiger128 = tiger128_test(
        pbkdf
    )

    # --------------------------------------------------------
    # 5. HAVAL192 test derivative
    # --------------------------------------------------------

    haval192 = haval192_test(
        tiger128 + pbkdf
    )

    # --------------------------------------------------------
    # 6. Adler-32 integrity value
    # --------------------------------------------------------

    adler32_value = zlib.adler32(
        haval192
    ) & 0xffffffff

    adler_bytes = adler32_value.to_bytes(
        4,
        "big"
    )

    # --------------------------------------------------------
    # 7. JOATT 64-bit identifier
    # --------------------------------------------------------

    identifier64 = sha256(
        b"JOATT-ID64|" +
        tiger128 +
        haval192 +
        adler_bytes
    )[:8]

    # --------------------------------------------------------
    # 8. Final JOATT 256-bit state
    # --------------------------------------------------------

    state256 = sha256(
        b"GODCHAIN-STATE256|" +
        root +
        pbkdf +
        tiger128 +
        haval192 +
        identifier64
    )

    return {

        "algorithm":
            "JOATT-TIGER128-HAVAL192-TEST",

        "network":
            NETWORK,

        "root_sha256":
            root.hex(),

        "pbkdf2_hmac_sha512":
            pbkdf.hex(),

        "tiger128_test":
            tiger128.hex(),

        "haval192_test":
            haval192.hex(),

        "adler32":
            f"{adler32_value:08x}",

        "identifier64":
            identifier64.hex(),

        "state256":
            state256.hex(),
    }


# ============================================================
# JOATT VALIDATION
# ============================================================

def validate_joatt(result: dict) -> bool:

    expected_lengths = {

        "root_sha256": 64,

        "pbkdf2_hmac_sha512": 128,

        "tiger128_test": 32,

        "haval192_test": 48,

        "adler32": 8,

        "identifier64": 16,

        "state256": 64,
    }

    for field, length in expected_lengths.items():

        if field not in result:
            return False

        if len(result[field]) != length:
            return False

        try:
            int(result[field], 16)

        except ValueError:
            return False

    return True


# ============================================================
# JOATT STATE PERSISTENCE
# ============================================================

def save_joatt_state(result: dict):

    data = {

        "name":
            "GODCHAIN",

        "network":
            NETWORK,

        "version":
            VERSION,

        "timestamp":
            time.time(),

        "result":
            result,
    }

    temporary = STATE_FILE.with_suffix(
        ".tmp"
    )

    temporary.write_text(
        json.dumps(
            data,
            indent=2
        )
    )

    temporary.replace(
        STATE_FILE
    )


# ============================================================
# BLOCK
# ============================================================

@dataclass
class Block:

    index: int

    timestamp: float

    previous_hash: str

    transactions: list

    nonce: int = 0

    hash: str = ""

    joatt_state: str = ""

    joatt_identifier: str = ""

    def header(self):

        return {

            "index":
                self.index,

            "timestamp":
                self.timestamp,

            "previous_hash":
                self.previous_hash,

            "transactions":
                self.transactions,

            "nonce":
                self.nonce,

            "joatt_state":
                self.joatt_state,

            "joatt_identifier":
                self.joatt_identifier,
        }

    def calculate_hash(self):

        return sha256_hex(
            canonical(
                self.header()
            )
        )

    def mine(self):

        prefix = "0" * DIFFICULTY

        while RUNNING:

            self.hash = self.calculate_hash()

            if self.hash.startswith(prefix):

                return True

            self.nonce += 1

        return False


# ============================================================
# GODCHAIN
# ============================================================

class GodChain:

    def __init__(self):

        self.chain = []

        self.pending = []

        if CHAIN_FILE.exists():

            try:

                self.load()

                if self.validate():

                    print(
                        "[CHAIN] Existing chain loaded."
                    )

                else:

                    print(
                        "[CHAIN] Invalid chain."
                    )

                    self.chain.clear()

                    self.create_genesis()

            except Exception as error:

                print(
                    "[CHAIN] Load error:",
                    error
                )

                self.chain.clear()

                self.create_genesis()

        else:

            self.create_genesis()

    # ========================================================
    # GENESIS
    # ========================================================

    def create_genesis(self):

        payload = (
            b"GOD-GENOME|" +
            b"JOATT|" +
            b"GENESIS|" +
            b"1011"
        )

        joatt_result = joatt(
            payload
        )

        if not validate_joatt(
            joatt_result
        ):

            raise RuntimeError(
                "Genesis JOATT validation failed"
            )

        genesis = Block(

            index=0,

            timestamp=0,

            previous_hash="0" * 64,

            transactions=[

                {

                    "type":
                        "GENESIS",

                    "network":
                        NETWORK,

                    "message":
                        "GODCHAIN TESTNET",

                    "joatt":
                        joatt_result[
                            "state256"
                        ],
                }
            ],

            joatt_state=
                joatt_result[
                    "state256"
                ],

            joatt_identifier=
                joatt_result[
                    "identifier64"
                ]
        )

        genesis.hash = (
            genesis.calculate_hash()
        )

        self.chain = [
            genesis
        ]

        self.save()

        save_joatt_state(
            joatt_result
        )

    # ========================================================
    # LATEST BLOCK
    # ========================================================

    @property
    def latest(self):

        return self.chain[-1]

    # ========================================================
    # TRANSACTION
    # ========================================================

    def add_transaction(
        self,
        sender,
        recipient,
        amount
    ):

        if amount <= 0:

            raise ValueError(
                "Transaction amount must be positive"
            )

        transaction = {

            "sender":
                sender,

            "recipient":
                recipient,

            "amount":
                amount,

            "timestamp":
                time.time(),
        }

        self.pending.append(
            transaction
        )

        return transaction

    # ========================================================
    # AUTOMATIC BLOCK MINING
    # ========================================================

    def mine_block(self):

        transactions = list(
            self.pending
        )

        transactions.append({

            "type":
                "MINING_REWARD",

            "sender":
                NETWORK,

            "recipient":
                "GOD_MINER",

            "amount":
                BLOCK_REWARD,

            "timestamp":
                time.time(),
        })

        # ----------------------------------------------------
        # Serialize transaction state for JOATT
        # ----------------------------------------------------

        payload = canonical(
            transactions
        )

        # Add current chain state to JOATT domain.
        payload = (
            self.latest.hash.encode() +
            b"|" +
            payload
        )

        # ----------------------------------------------------
        # JOATT transformation
        # ----------------------------------------------------

        joatt_result = joatt(
            payload
        )

        if not validate_joatt(
            joatt_result
        ):

            raise RuntimeError(
                "JOATT validation failed"
            )

        save_joatt_state(
            joatt_result
        )

        # ----------------------------------------------------
        # Create block
        # ----------------------------------------------------

        block = Block(

            index=
                len(self.chain),

            timestamp=
                time.time(),

            previous_hash=
                self.latest.hash,

            transactions=
                transactions,

            joatt_state=
                joatt_result[
                    "state256"
                ],

            joatt_identifier=
                joatt_result[
                    "identifier64"
                ],
        )

        print()
        print(
            f"[MINING] block={block.index}"
        )

        print(
            "[JOATT] "
            f"id64={block.joatt_identifier}"
        )

        print(
            "[JOATT] "
            f"state256={block.joatt_state}"
        )

        start = time.time()

        if not block.mine():

            return False

        elapsed = (
            time.time() - start
        )

        self.chain.append(
            block
        )

        self.pending.clear()

        print(
            f"[BLOCK] {block.index} "
            f"nonce={block.nonce} "
            f"time={elapsed:.3f}s"
        )

        print(
            f"[HASH] {block.hash}"
        )

        return True

    # ========================================================
    # CHAIN VALIDATION
    # ========================================================

    def validate(self):

        if not self.chain:

            return False

        # ----------------------------------------------------
        # Genesis
        # ----------------------------------------------------

        genesis = self.chain[0]

        if genesis.previous_hash != (
            "0" * 64
        ):

            return False

        if genesis.hash != (
            genesis.calculate_hash()
        ):

            return False

        # ----------------------------------------------------
        # Remaining blocks
        # ----------------------------------------------------

        for i in range(
            1,
            len(self.chain)
        ):

            current = self.chain[i]

            previous = self.chain[i - 1]

            # Hash integrity
            if current.hash != (
                current.calculate_hash()
            ):

                return False

            # Chain linkage
            if current.previous_hash != (
                previous.hash
            ):

                return False

            # Proof of work
            if not current.hash.startswith(
                "0" * DIFFICULTY
            ):

                return False

            # JOATT state format
            if len(
                current.joatt_state
            ) != 64:

                return False

            if len(
                current.joatt_identifier
            ) != 16:

                return False

        return True

    # ========================================================
    # BALANCE
    # ========================================================

    def balance(
        self,
        address
    ):

        balance = 0

        for block in self.chain:

            for tx in block.transactions:

                if (
                    tx.get("sender")
                    == address
                ):

                    balance -= (
                        tx["amount"]
                    )

                if (
                    tx.get("recipient")
                    == address
                ):

                    balance += (
                        tx["amount"]
                    )

        return balance

    # ========================================================
    # SAVE CHAIN
    # ========================================================

    def save(self):

        data = {

            "name":
                "GODCHAIN",

            "network":
                NETWORK,

            "version":
                VERSION,

            "difficulty":
                DIFFICULTY,

            "block_reward":
                BLOCK_REWARD,

            "chain": [

                asdict(block)

                for block
                in self.chain
            ],
        }

        temporary = (
            CHAIN_FILE.with_suffix(
                ".tmp"
            )
        )

        temporary.write_text(
            json.dumps(
                data,
                indent=2
            )
        )

        temporary.replace(
            CHAIN_FILE
        )

    # ========================================================
    # LOAD CHAIN
    # ========================================================

    def load(self):

        data = json.loads(
            CHAIN_FILE.read_text()
        )

        self.chain = [

            Block(
                **block
            )

            for block
            in data["chain"]
        ]


# ============================================================
# SIGNAL HANDLING
# ============================================================

def shutdown(
    signum,
    frame
):

    global RUNNING

    print(
        "\n[SHUTDOWN] Request received."
    )

    RUNNING = False


signal.signal(
    signal.SIGINT,
    shutdown
)

signal.signal(
    signal.SIGTERM,
    shutdown
)


# ============================================================
# AUTOMATION ENGINE
# ============================================================

def automate():

    chain = GodChain()

    print()
    print("=" * 64)
    print(
        "       GODCHAIN / JOATT AUTOMATION"
    )
    print("=" * 64)

    print(
        f"Network       : {NETWORK}"
    )

    print(
        f"Version       : {VERSION}"
    )

    print(
        f"Difficulty    : {DIFFICULTY}"
    )

    print(
        f"Block reward  : {BLOCK_REWARD}"
    )

    print(
        f"Interval      : {BLOCK_INTERVAL}s"
    )

    print("=" * 64)

    while RUNNING:

        try:

            # ------------------------------------------------
            # 1. Validate existing chain
            # ------------------------------------------------

            if not chain.validate():

                raise RuntimeError(
                    "CHAIN VALIDATION FAILED"
                )

            print(
                f"[VALID] height="
                f"{len(chain.chain) - 1}"
            )

            # ------------------------------------------------
            # 2. Mine new block
            # ------------------------------------------------

            chain.mine_block()

            # ------------------------------------------------
            # 3. Validate resulting chain
            # ------------------------------------------------

            if not chain.validate():

                raise RuntimeError(
                    "POST-MINING VALIDATION FAILED"
                )

            print(
                "[VALID] post-mining"
            )

            # ------------------------------------------------
            # 4. Persist chain
            # ------------------------------------------------

            chain.save()

            print(
                f"[SAVE] {CHAIN_FILE}"
            )

            print(
                f"[SAVE] {STATE_FILE}"
            )

            # ------------------------------------------------
            # 5. Wait
            # ------------------------------------------------

            for _ in range(
                BLOCK_INTERVAL
            ):

                if not RUNNING:

                    break

                time.sleep(1)

        except Exception as error:

            print(
                f"[ERROR] {error}"
            )

            time.sleep(5)

    # ========================================================
    # CLEAN SHUTDOWN
    # ========================================================

    chain.save()

    print()
    print("=" * 64)
    print(
        "GODCHAIN STOPPED SAFELY"
    )

    print(
        f"Final height: "
        f"{len(chain.chain) - 1}"
    )

    print("=" * 64)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="GODCHAIN / JOATT engine with optional Bitcoin WIF generation"
    )
    parser.add_argument(
        "--generate-wif",
        action="store_true",
        help="Generate one random Bitcoin mainnet WIF and exit"
    )
    parser.add_argument(
        "--garble-wif",
        action="store_true",
        help="Prompt for a custom Garble seed, PBKDF2 salt, and iteration count"
    )
    args = parser.parse_args()

    if args.garble_wif:
        prompt_garble_wif()
    elif args.generate_wif:
        print("Bitcoin mainnet WIF (compressed public-key format):")
        print(generate_wif())
        print("Keep this secret. Anyone with this WIF can spend its funds.")
        print("This key is independent of the JOATT state and GODCHAIN testnet.")
    else:
        automate()
