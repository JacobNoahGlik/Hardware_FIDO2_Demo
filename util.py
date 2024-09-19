import os
import hmac
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature
import time
import datetime
import string
import random

class YubiKey:
    def __init__(self, secret:bytes|None=None):
        if not secret:
            secret = YubiKey._gen_secret(print_fun=True)
        self._device_secret: bytes = secret
        self.ID: str = get_rand_id(12)
    
    def register_account(self, RP_ID, account):
        pass

    def _generate_key_pair(self, rp_id, account_info, print_debug=False):
        display = print if print_debug else void
        display('Generating key pair inside YubiKey...')
        secret_material = self._device_secret + rp_id.encode('utf-8') + account_info.encode('utf-8')
        display(f"     1.     Known: {rp_id=}, {account_info=}, {self._device_secret=}")
        display(f'        Concat to get secret material: {secret_material}\n')
        
        # Use HMAC-SHA256 to derive a key from the secret material
        derived_key = hmac.new(self._device_secret, secret_material, sha256).digest()
        display('     2. Calculate key from secret')

        # Convert derived key to an integer (this will act as a deterministic seed for EC key generation)
        seed = int.from_bytes(derived_key, byteorder='big') % ec.SECP256R1().key_size
        display('     3. Convert derived key into integer to use as seed for EC key generation')

        # Generate the private key deterministically using the derived seed
        private_key = ec.derive_private_key(seed, ec.SECP256R1(), default_backend())
        display('     4. Generate private key using calculated seed deterministically')

        # Derive the public key from the private key
        public_key = private_key.public_key()
        display('     5. Derive public key from private key')

        # Serialize public key for transmission/storage (compressed point format)
        public_key_bytes = public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

        # Print or return the generated public key
        display(f"Public Key (Compressed): {public_key_bytes.hex()}")
        display(f'Private Key {YubiKey._private_key_to_number(private_key)}')
        return (private_key, public_key)
    
    def sign(self, nonce: bytes, private_key):
        """
        Signs the given nonce using the private key and returns the signature.
        """
        signature = private_key.sign(
            nonce,
            ec.ECDSA(hashes.SHA256())  # Using ECDSA with SHA-256
        )
        return signature
    
    @staticmethod
    def _private_key_to_number(private_key) -> int:
        return private_key.private_numbers().private_value
    
    
    @staticmethod
    def _gen_secret(print_fun=False) -> bytes:
        secret = os.urandom(32)
        print("No secret specified. Generating random secret", end='\r')
        time.sleep(0.3)
        print("No secret specified. Generating random secret.", end='\r')
        time.sleep(0.21)
        print("No secret specified. Generating random secret..", end='\r')
        time.sleep(0.28)
        print("No secret specified. Generating random secret...", end='\r')
        time.sleep(0.47)
        print(f"No secret specified. Generating random secret   {secret}")
        return secret
    
class Account:
    def __init__(self, name, password_hash):
        self.name: str = name
        self.password_hash: bytes = password_hash
        self.public_key = None

class SessionToken:
    def __init__(self, account: str, hours: float, auth_type: str, data: bytes = os.urandom(16)):
        self.for_account = account
        self.auth_type = auth_type
        self.nonces = {}

        # hidden
        self._expires_on = datetime.datetime.now() + hours * 3600
        self._data = data
        self._value_string = f'Account={self.for_account},atype={self.auth_type},expires={self._expires_on},nonce={self._data.hex()}'
    def value(self):
        return hash(self._value_string)
    def reinstate(self, new_hours: float) -> None:
        self._expires_on = datetime.datetime.now() + new_hours * 3600
    def timmed_out(self) -> bool:
        return datetime.datetime.now() > self._expires_on
    def is_valid(self, account: str, auth_type: str) -> bool:
        if self.timmed_out():
            return False
        value_string = f'Account={account},atype={auth_type},expires={self._expires_on},nonce={self._data.hex()}'
        return hash(value_string) == self.value()  # validate
    def add_nonce(self, nonce: str) -> str:
        n_id = get_rand_id(12)
        self.nonces[n_id] = nonce
        return n_id
    def is_same(self, thash) -> bool:
        return self.value() == thash

class Challenge:
    def __init__(self, RP_ID, username, token_1FA, NonceID, Nonce):
        self.RP_ID = RP_ID
        self.username = username
        self.token_1FA = token_1FA
        self.NonceID = NonceID
        self.nonce = Nonce

class RelyingParty:
    def __init__(self, name: str):
        self.name = name
        self.accounts = {}
        self._longest_account_length = len('Username')  # used for displaying in table
        self.tokens = {}

    def number_of_accounts(self):
        return len(self.accounts)

    def _add_token(self, account, token):
        if account not in self.tokens.keys():
            raise ValueError(f"Account '{account}' does not exist.")
        self.tokens[account].append(token)

    def add_account(self, account_name: str, account_password: str = 'password'):
        if account_name in self.accounts.keys():
            raise ValueError(f"Account '{account_name}' already exists.")
        self.tokens[account_name] = []
        self.accounts[account_name] = Account(
            account_name,
            hash(account_password)
        )
        self._longest_account_length = max(self._longest_account_length, len(account_name))
    def update_account_password(self, account_name: str, new_password: str) -> None:
        if account_name not in self.accounts.keys():
            raise ValueError(f"Account '{account_name}' does not exist.")
        self.accounts[account_name].password_hash = hash(new_password)
    def update_account_public_key(self, account_name: str, public_key) -> None:
        if account_name not in self.accounts.keys():
            raise ValueError(f"Account '{account_name}' does not exist.")
        self.accounts[account_name].public_key = public_key
    def display_table(self):
        print(f"\nRelying Party '{self.name}' accounts table:")
        dotted_line = '-' * (self._longest_account_length + 2)
        seper = f'|{dotted_line}|---------------------------------|------------|'
        print('_' * len(seper))
        print('| ' + 'Username'.center(self._longest_account_length) + ' |          Password Hash          | Public Key |')
        print(seper)
        for account_name, account in self.accounts.items():
            username = account_name.center(self._longest_account_length)
            password_hash = f'0x{account.password_hash.hex()}'[:28] + '...'
            public_key = '  Exists  ' if account.public_key else '   None   '
            print(f'| {username} | {password_hash} | {public_key} |')
        print('‾' * len(seper))
    def _generate_token(self, account: str, hours: float, auth_type: str) -> bytes:
        new_token = SessionToken(
            account,
            hours,
            auth_type,
            os.urandom(16)
        )
        self._add_token(
            account, 
            new_token
        )
        return new_token.value()
    def prune_tokens(self) -> None:
        for user, tokens in self.tokens.items():
            self.tokens[user] = [
                token for token in tokens if not token.timmed_out()
            ]
    def user_has_access(self, account:str, auth_type:str, spec_token = None) -> bool:
        self.prune_tokens()
        for token in self.tokens[account]:
            # validate token for this user and this action
            if token.is_valid(account, auth_type) and \
                (not spec_token or token.is_same(spec_token)): # will only run if spec_token is not None
                return True
        return False
    def get_token(self, account:str, auth_type:str, spec_token = None):
        self.prune_tokens()
        for token in self.tokens[account]:
            # validate token for this user and this action
            if token.is_valid(account, auth_type) and \
                (not spec_token or token.is_same(spec_token)): # will only run if spec_token is not None
                return token
        return None
    def valid_login(self, username: str, password: str) -> bool:
        if username not in self.accounts.keys():
            return False
        return self.accounts[username].password_hash == hash(password)
    def grant_session_token_1FA(self, username: str, password: str) -> bytes | None:
        if self.valid_login(username, password):
            # grant user token for 1FA
            # it will time out in 3 minutes (0.05 hours) unless user authenticates with 2FA
            # post-2FA: new token will be granted to user (1 hour exp) assuming this token is still valid
            return self._generate_token(username, 0.05, '1FA')
        return None # failed varification (username/password wrong)
    def request_challenge(self, username: str, token: bytes) -> Challenge:
        TK = self.get_token(username, '1FA', token)
        if not TK:
            raise ValueError('Permission denied - token not found or expired')
        nonce = os.urandom(32)
        return Challenge(
            self.name,
            username,
            token,
            TK.add_nonce(nonce),
            nonce
        )
    def requires_2FA(self, username: str) -> bool:
        if username not in self.accounts:
            raise ValueError(f'User "{username}" not found')
        return not not self.accounts[username].public_key

    





def get_rand_id(length: int) -> str:
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
    
def hash(input:str)->bytes:
    sha256_instance = sha256()
    sha256_instance.update(input.encode('utf8'))
    return sha256_instance.digest()

def is_signed(nonce: bytes, public_key, response: bytes) -> bool:
    """
    Verifies that the given response is a valid signature for the nonce, using the public key.
    """
    try:
        # Verify the signature using the public key
        public_key.verify(
            response,
            nonce,
            ec.ECDSA(hashes.SHA256())  # Using ECDSA with SHA-256
        )
        return True
    except InvalidSignature:
        return False
    

def void(*args, **kwargs):
    pass