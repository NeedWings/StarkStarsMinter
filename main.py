from starknet_py.hash import transaction 
from starknet_py.hash.address import compute_address
from starknet_py.net.account.account import Account as StarkNativeAccount
from starknet_py.net.client import Client
from starknet_py.net.gateway_client import GatewayClient
from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.net.models import StarknetChainId
from starknet_py.net.networks import MAINNET
from starknet_py.net.signer.stark_curve_signer import KeyPair
from starknet_py.contract import Contract, PreparedFunctionCall
from starknet_py.hash.utils import message_signature, private_to_stark_key, verify_message_signature, compute_hash_on_elements
from starknet_py.net.models import AddressRepresentation, StarknetChainId, parse_address
from starknet_py.net.account.account_deployment_result import AccountDeploymentResult
from starknet_py.net.account.account import _add_max_fee_to_transaction
from starknet_py.net.signer import BaseSigner
import time
from abc import abstractmethod, ABC
import asyncio
import random
#from curl_cffi import requests as mod_requests
from starknet_py.utils.iterable import ensure_iterable
from starknet_py.net.models.transaction import (
    AccountTransaction,
    Declare,
    DeclareV2,
    DeployAccount,
    Invoke,
)
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union, cast
from starknet_py.constants import DEFAULT_ENTRY_POINT_SELECTOR
from starknet_py.hash.transaction import (
    TransactionHashPrefix,
    compute_declare_transaction_hash,
    compute_declare_v2_transaction_hash,
    compute_deploy_account_transaction_hash,
    compute_transaction_hash,
)
from starknet_py.net.client_models import (
    Call,
    Calls,
    EstimatedFee,
    Hash,
    SentTransactionResponse,
    Tag,
)
from loguru import logger
from settings import *
import requests
chain = StarknetChainId.MAINNET
client = FullNodeClient(RPC)

STARK_TOKEN_ABI = [{"name":"Uint256","size":2,"type":"struct","members":[{"name":"low","type":"felt","offset":0},{"name":"high","type":"felt","offset":1}]},{"data":[{"name":"from_","type":"felt"},{"name":"to","type":"felt"},{"name":"value","type":"Uint256"}],"keys":[],"name":"Transfer","type":"event"},{"data":[{"name":"owner","type":"felt"},{"name":"spender","type":"felt"},{"name":"value","type":"Uint256"}],"keys":[],"name":"Approval","type":"event"},{"name":"name","type":"function","inputs":[],"outputs":[{"name":"name","type":"felt"}],"stateMutability":"view"},{"name":"symbol","type":"function","inputs":[],"outputs":[{"name":"symbol","type":"felt"}],"stateMutability":"view"},{"name":"totalSupply","type":"function","inputs":[],"outputs":[{"name":"totalSupply","type":"Uint256"}],"stateMutability":"view"},{"name":"decimals","type":"function","inputs":[],"outputs":[{"name":"decimals","type":"felt"}],"stateMutability":"view"},{"name":"balanceOf","type":"function","inputs":[{"name":"account","type":"felt"}],"outputs":[{"name":"balance","type":"Uint256"}],"stateMutability":"view"},{"name":"allowance","type":"function","inputs":[{"name":"owner","type":"felt"},{"name":"spender","type":"felt"}],"outputs":[{"name":"remaining","type":"Uint256"}],"stateMutability":"view"},{"name":"permittedMinter","type":"function","inputs":[],"outputs":[{"name":"minter","type":"felt"}],"stateMutability":"view"},{"name":"initialized","type":"function","inputs":[],"outputs":[{"name":"res","type":"felt"}],"stateMutability":"view"},{"name":"get_version","type":"function","inputs":[],"outputs":[{"name":"version","type":"felt"}],"stateMutability":"view"},{"name":"get_identity","type":"function","inputs":[],"outputs":[{"name":"identity","type":"felt"}],"stateMutability":"view"},{"name":"initialize","type":"function","inputs":[{"name":"init_vector_len","type":"felt"},{"name":"init_vector","type":"felt*"}],"outputs":[]},{"name":"transfer","type":"function","inputs":[{"name":"recipient","type":"felt"},{"name":"amount","type":"Uint256"}],"outputs":[{"name":"success","type":"felt"}]},{"name":"transferFrom","type":"function","inputs":[{"name":"sender","type":"felt"},{"name":"recipient","type":"felt"},{"name":"amount","type":"Uint256"}],"outputs":[{"name":"success","type":"felt"}]},{"name":"approve","type":"function","inputs":[{"name":"spender","type":"felt"},{"name":"amount","type":"Uint256"}],"outputs":[{"name":"success","type":"felt"}]},{"name":"increaseAllowance","type":"function","inputs":[{"name":"spender","type":"felt"},{"name":"added_value","type":"Uint256"}],"outputs":[{"name":"success","type":"felt"}]},{"name":"decreaseAllowance","type":"function","inputs":[{"name":"spender","type":"felt"},{"name":"subtracted_value","type":"Uint256"}],"outputs":[{"name":"success","type":"felt"}]},{"name":"permissionedMint","type":"function","inputs":[{"name":"recipient","type":"felt"},{"name":"amount","type":"Uint256"}],"outputs":[]},{"name":"permissionedBurn","type":"function","inputs":[{"name":"account","type":"felt"},{"name":"amount","type":"Uint256"}],"outputs":[]}]


def req(url: str, **kwargs):
    try:
        resp = requests.get(url, **kwargs)
        if resp.status_code == 200:
            return resp.json()
        else:
            logger.error("Bad status code, will try again")
            pass
    except Exception as error:
        logger.error(f"Requests error: {error}")

def import_stark_account(private_key: int):
    if useAdvanced:
        key_pair = KeyPair.from_private_key(private_key)
        salt = key_pair.public_key
        if Provider.lower() == "argent" or Provider.lower() == "argent_newest":
            account_initialize_call_data = [key_pair.public_key, 0]
        elif Provider.lower() == "braavos" or Provider.lower() == "braavos_newest":
            account_initialize_call_data = [key_pair.public_key]
        else:
            logger.error(f"Selected unsupported wallet provider: {Provider.lower()}. Please select one of this: argent, braavos")
            return
        class_hash = int(class_hash, 16)
        call_data = [
                int(implementation, 16),
                int(selector, 16),
                len(account_initialize_call_data),
                *account_initialize_call_data
            ]
    else:
        if Provider.lower() == "argent":
            class_hash = 0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918

            key_pair = KeyPair.from_private_key(private_key)
            salt = key_pair.public_key


            account_initialize_call_data = [key_pair.public_key, 0]

            call_data = [
                0x33434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2,
                0x79dc0da7c54b95f10aa182ad0a46400db63156920adb65eca2654c0945a463,
                len(account_initialize_call_data),
                *account_initialize_call_data
            ]
        elif Provider.lower() == "argent_newest":
            class_hash = 0x01a736d6ed154502257f02b1ccdf4d9d1089f80811cd6acad48e6b6a9d1f2003

            key_pair = KeyPair.from_private_key(private_key)
            salt = key_pair.public_key


            account_initialize_call_data = [key_pair.public_key, 0]

            call_data = [
                *account_initialize_call_data
            ]
        elif Provider.lower() == "braavos":
            class_hash = 0x03131fa018d520a037686ce3efddeab8f28895662f019ca3ca18a626650f7d1e
            key_pair = KeyPair.from_private_key(private_key)
            salt = key_pair.public_key
            account_initialize_call_data = [key_pair.public_key]

            call_data = [
                0x5aa23d5bb71ddaa783da7ea79d405315bafa7cf0387a74f4593578c3e9e6570,
                0x2dd76e7ad84dbed81c314ffe5e7a7cacfb8f4836f01af4e913f275f89a3de1a,
                len(account_initialize_call_data),
                *account_initialize_call_data
            ]
        elif Provider.lower() == "braavos_newest":
            class_hash = 0x03131fa018d520a037686ce3efddeab8f28895662f019ca3ca18a626650f7d1e
            key_pair = KeyPair.from_private_key(private_key)
            salt = key_pair.public_key
            account_initialize_call_data = [key_pair.public_key]

            call_data = [
                0x5aa23d5bb71ddaa783da7ea79d405315bafa7cf0387a74f4593578c3e9e6570,
                0x2dd76e7ad84dbed81c314ffe5e7a7cacfb8f4836f01af4e913f275f89a3de1a,
                len(account_initialize_call_data),
                *account_initialize_call_data
            ]
        elif Provider.lower() == "argent_old":
            class_hash = 0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918
            key_pair = KeyPair.from_private_key(private_key)
            salt = key_pair.public_key
            account_initialize_call_data = [key_pair.public_key]

            call_data = [
                0x1a7820094feaf82d53f53f214b81292d717e7bb9a92bb2488092cd306f3993f,
                0x79dc0da7c54b95f10aa182ad0a46400db63156920adb65eca2654c0945a463,
                len(account_initialize_call_data),
                *account_initialize_call_data
            ]
        else:
            logger.error(f"Selected unsupported wallet provider: {Provider.lower()}. Please select one of this: argent, braavos")
            return
    address = compute_address(
        salt=salt,
        class_hash=class_hash,  
        constructor_calldata=call_data,
        deployer_address=0,
    )
    

    account = StarkNativeAccount(
            address=address, client=client, key_pair=key_pair, chain=chain
        )

    return account, call_data, salt, class_hash


async def sleeping(address, error = False):
    if error:
        rand_time = random.randint(ErrorSleepeng[0], ErrorSleepeng[1])
    else:
        rand_time = random.randint(TaskSleep[0], TaskSleep[1])
    logger.info(f'[{address}] sleeping {rand_time} s')
    await asyncio.sleep(rand_time)

async def handle_dangerous_request(func, message, address = "", *args):
    
    while True:
        try:
            return await func(*args)
        except Exception as e:
            logger.error(f"[{address}] {message}: {e}")
            await sleeping(address, True)

class BaseStarkAccount(ABC):
    stark_native_account: StarkNativeAccount = None
    formatted_hex_address: str = None
    @abstractmethod
    async def send_txn(self, calldata):
        """sends transaction"""
        pass
    
    @abstractmethod
    def get_address(self):
        "returns address"
        pass

    @abstractmethod
    async def get_balance(self, token: int = None, symbol: str = "ETH"):
        pass

class StarkAccount(BaseStarkAccount):

    def __init__(self, stark_native_account: StarkNativeAccount, call_data, salt, class_hash) -> None:
        self.stark_native_account = stark_native_account
        self.call_data = call_data
        self.salt = salt
        self.class_hash = class_hash
        self.formatted_hex_address = "0x" + "0"*(64 - len(hex(stark_native_account.address)[2::])) + hex(stark_native_account.address)[2::]
        self.client = stark_native_account.client
        self.address = self.stark_native_account.address

    def get_address(self):
        return self.formatted_hex_address
    
    async def get_balance(self, token: int = None, symbol: str = "ETH"):
        return await handle_dangerous_request(self.stark_native_account.get_balance, f"can't get balance of {symbol}. Error", self.formatted_hex_address, token)

            
    async def send_txn(self, calldata):
        
        resp = await self.get_invocation(calldata)
        if resp == -3:
            return -3, ""
        try:
            logger.success(f"[{self.formatted_hex_address}] sending txn with hash: {hex(resp.transaction_hash)}")
            await self.stark_native_account.client.wait_for_tx(resp.transaction_hash)
            logger.success(f"[{self.formatted_hex_address}] tnx has sent! Hash: {hex(resp.transaction_hash)}")
            return 1, hex(resp.transaction_hash)
        except Exception as e:
            logger.error(f"[{self.formatted_hex_address}]  got error while sending txn: {hex(resp.transaction_hash)}. Error: {e}")
            return -1, ""

    async def get_invocation(self, calls):
        try:
            invocation = await self.stark_native_account.execute(calls=calls, auto_estimate=True, cairo_version=cairo_version)
            return invocation
        except Exception as e:
            logger.error(f"[{self.formatted_hex_address}] can't create transaction. Error:{e}")
            return -3

class Token():
    def __init__(self, symbol: str, contract_address: int, decimals, stable = False) -> None:
        self.decimals = decimals
        self.symbol: str = symbol
        self.contract_address = contract_address
        self.stable = stable

    def get_approve_call(self, amount: float, spender: int, sender: BaseStarkAccount):
        contract = Contract(self.contract_address, STARK_TOKEN_ABI, sender.stark_native_account)
        decimals = self.decimals
        call = contract.functions["approve"].prepare(
            spender, int(amount*10**decimals)
        )
        return call
    
    def get_approve_call_wei(self, amount: int, spender: int, sender: BaseStarkAccount):
        contract = Contract(self.contract_address, STARK_TOKEN_ABI, sender.stark_native_account)
        decimals = self.decimals

        call = contract.functions["approve"].prepare(
            spender, amount
        )
        return call
    
    def get_price(self):
        if self.stable:
            return 1
        else:
            def __find__(ticker: str, rates: list):
                for k in rates:
                    name = k.get("symbol")
                    if name == ticker.upper() + 'USDT':
                        return float(k.get("price"))
            while True:
                response = req("https://api.binance.com/api/v3/ticker/price")
                if type(response) is list:
                    return __find__(self.symbol, response)
                else:
                    print(f'Cant get response from binance, tring again...')
                    time.sleep(5)

    def get_usd_value(self, amount):
        return self.get_price()*amount

class StarkStars:

    contracts = [
        0x04d70758d392e0563a8a0076d4b72847048dea7d65199c50eabc8e855ca62931,
    0x02ac5be4b280f6625a56b944bab9d985fbbc9f180ff4b08b854b63d284b7f6ae,
    0x5f650c37f8a15e33f01b3c28365637ca72a536014c4b8f84271c20a4c24aef8,
    0x27c8cb6bf861df8b86ebda8656430aeec9c1c2c66e9f99d3c8587df5fcb1c9c,
    0x5e69ae81aed84dfadb4af03a67ce702e353db7f7f87ad833cf08df36e427704,
    0x6b1e710f97e0d4701123c256a6f4cce4ffdc2bf6f439b42f48d08585feab123,
    0x62b37f6ced8e742ecd4baa51321e0c39ab089183a1ca0b24138e1fb0f5083a8,
    0x656c27654b2b3c4ae3e8f5f6bc2a4863a79fb74cb7b2999af9dde2ad1fe3cb5,
    0x265f815955a1595e6859f3ad80533f15b2b57311d25fed6f01e4c530c1f1b0f,
    0x2c69468dd31a6837bc4a10357bc940f41f6d0acebe74376c940195915cede1d,
    0x40cb48ec6f61e1bbc5b62ee2f7a7df8151712394248c90db4f12f7a61ce993,
    0x4aa60106c215809a9dfc2ac2d64aa166f1185e9dc7212497a837f7d60bfb1c3,
    0x2ff063073208cd8b867c727be3a5f46c54d31ae1c1fbf7506ffaca673990f,
    0x7bc362ffdbd67ff80b49e95f0b9996ad89f9f6ea9186d209ece577df429e69b,
    0x267217f031a1d794446943ba45175153d18202b3db246db6b15b0c772f9ec09,
    0x21461d8b7593ef6d39a83229750d61a23b7f45b91baafb5ad1b2da6abf13c0,
    0x4c7999fb6eeb958240abdecdddc2331f35b5f99f1e60e29ef0e4e26f23e182b,
    0x50e02814bd1900efd33148dbed847e7fe42a2a2de6dd444366ead20cf8dedc5,
    0x3883b7148c475f170c4b1a21e37b15b9261e86f9c203098ff1c3b7f8cf72f73,
    0x394034029c6c0773397a2c79eb9b7df8f080613bfec83d93c3cd5e7c0b993ce,
    ]
    ABI = [{"name":"SRC5Impl","type":"impl","interface_name":"openzeppelin::introspection::interface::ISRC5"},{"name":"core::bool","type":"enum","variants":[{"name":"False","type":"()"},{"name":"True","type":"()"}]},{"name":"openzeppelin::introspection::interface::ISRC5","type":"interface","items":[{"name":"supports_interface","type":"function","inputs":[{"name":"interface_id","type":"core::felt252"}],"outputs":[{"type":"core::bool"}],"state_mutability":"view"}]},{"name":"SRC5CamelImpl","type":"impl","interface_name":"openzeppelin::introspection::interface::ISRC5Camel"},{"name":"openzeppelin::introspection::interface::ISRC5Camel","type":"interface","items":[{"name":"supportsInterface","type":"function","inputs":[{"name":"interfaceId","type":"core::felt252"}],"outputs":[{"type":"core::bool"}],"state_mutability":"view"}]},{"name":"ERC721MetadataImpl","type":"impl","interface_name":"openzeppelin::token::erc721::interface::IERC721Metadata"},{"name":"core::integer::u256","type":"struct","members":[{"name":"low","type":"core::integer::u128"},{"name":"high","type":"core::integer::u128"}]},{"name":"openzeppelin::token::erc721::interface::IERC721Metadata","type":"interface","items":[{"name":"name","type":"function","inputs":[],"outputs":[{"type":"core::felt252"}],"state_mutability":"view"},{"name":"symbol","type":"function","inputs":[],"outputs":[{"type":"core::felt252"}],"state_mutability":"view"},{"name":"token_uri","type":"function","inputs":[{"name":"token_id","type":"core::integer::u256"}],"outputs":[{"type":"core::felt252"}],"state_mutability":"view"}]},{"name":"ERC721MetadataCamelOnlyImpl","type":"impl","interface_name":"openzeppelin::token::erc721::interface::IERC721MetadataCamelOnly"},{"name":"openzeppelin::token::erc721::interface::IERC721MetadataCamelOnly","type":"interface","items":[{"name":"tokenURI","type":"function","inputs":[{"name":"tokenId","type":"core::integer::u256"}],"outputs":[{"type":"core::felt252"}],"state_mutability":"view"}]},{"name":"ERC721Impl","type":"impl","interface_name":"openzeppelin::token::erc721::interface::IERC721"},{"name":"core::array::Span::<core::felt252>","type":"struct","members":[{"name":"snapshot","type":"@core::array::Array::<core::felt252>"}]},{"name":"openzeppelin::token::erc721::interface::IERC721","type":"interface","items":[{"name":"balance_of","type":"function","inputs":[{"name":"account","type":"core::starknet::contract_address::ContractAddress"}],"outputs":[{"type":"core::integer::u256"}],"state_mutability":"view"},{"name":"owner_of","type":"function","inputs":[{"name":"token_id","type":"core::integer::u256"}],"outputs":[{"type":"core::starknet::contract_address::ContractAddress"}],"state_mutability":"view"},{"name":"transfer_from","type":"function","inputs":[{"name":"from","type":"core::starknet::contract_address::ContractAddress"},{"name":"to","type":"core::starknet::contract_address::ContractAddress"},{"name":"token_id","type":"core::integer::u256"}],"outputs":[],"state_mutability":"external"},{"name":"safe_transfer_from","type":"function","inputs":[{"name":"from","type":"core::starknet::contract_address::ContractAddress"},{"name":"to","type":"core::starknet::contract_address::ContractAddress"},{"name":"token_id","type":"core::integer::u256"},{"name":"data","type":"core::array::Span::<core::felt252>"}],"outputs":[],"state_mutability":"external"},{"name":"approve","type":"function","inputs":[{"name":"to","type":"core::starknet::contract_address::ContractAddress"},{"name":"token_id","type":"core::integer::u256"}],"outputs":[],"state_mutability":"external"},{"name":"set_approval_for_all","type":"function","inputs":[{"name":"operator","type":"core::starknet::contract_address::ContractAddress"},{"name":"approved","type":"core::bool"}],"outputs":[],"state_mutability":"external"},{"name":"get_approved","type":"function","inputs":[{"name":"token_id","type":"core::integer::u256"}],"outputs":[{"type":"core::starknet::contract_address::ContractAddress"}],"state_mutability":"view"},{"name":"is_approved_for_all","type":"function","inputs":[{"name":"owner","type":"core::starknet::contract_address::ContractAddress"},{"name":"operator","type":"core::starknet::contract_address::ContractAddress"}],"outputs":[{"type":"core::bool"}],"state_mutability":"view"}]},{"name":"ERC721CamelOnlyImpl","type":"impl","interface_name":"openzeppelin::token::erc721::interface::IERC721CamelOnly"},{"name":"openzeppelin::token::erc721::interface::IERC721CamelOnly","type":"interface","items":[{"name":"balanceOf","type":"function","inputs":[{"name":"account","type":"core::starknet::contract_address::ContractAddress"}],"outputs":[{"type":"core::integer::u256"}],"state_mutability":"view"},{"name":"ownerOf","type":"function","inputs":[{"name":"tokenId","type":"core::integer::u256"}],"outputs":[{"type":"core::starknet::contract_address::ContractAddress"}],"state_mutability":"view"},{"name":"transferFrom","type":"function","inputs":[{"name":"from","type":"core::starknet::contract_address::ContractAddress"},{"name":"to","type":"core::starknet::contract_address::ContractAddress"},{"name":"tokenId","type":"core::integer::u256"}],"outputs":[],"state_mutability":"external"},{"name":"safeTransferFrom","type":"function","inputs":[{"name":"from","type":"core::starknet::contract_address::ContractAddress"},{"name":"to","type":"core::starknet::contract_address::ContractAddress"},{"name":"tokenId","type":"core::integer::u256"},{"name":"data","type":"core::array::Span::<core::felt252>"}],"outputs":[],"state_mutability":"external"},{"name":"setApprovalForAll","type":"function","inputs":[{"name":"operator","type":"core::starknet::contract_address::ContractAddress"},{"name":"approved","type":"core::bool"}],"outputs":[],"state_mutability":"external"},{"name":"getApproved","type":"function","inputs":[{"name":"tokenId","type":"core::integer::u256"}],"outputs":[{"type":"core::starknet::contract_address::ContractAddress"}],"state_mutability":"view"},{"name":"isApprovedForAll","type":"function","inputs":[{"name":"owner","type":"core::starknet::contract_address::ContractAddress"},{"name":"operator","type":"core::starknet::contract_address::ContractAddress"}],"outputs":[{"type":"core::bool"}],"state_mutability":"view"}]},{"name":"IStarkStarsImpl","type":"impl","interface_name":"achievments::contract::contract::IStarkStars"},{"name":"achievments::contract::contract::IStarkStars","type":"interface","items":[{"name":"get_price","type":"function","inputs":[],"outputs":[{"type":"core::integer::u256"}],"state_mutability":"view"},{"name":"mint","type":"function","inputs":[],"outputs":[],"state_mutability":"external"},{"name":"withdraw","type":"function","inputs":[],"outputs":[],"state_mutability":"external"},{"name":"set_price","type":"function","inputs":[{"name":"price","type":"core::integer::u256"}],"outputs":[],"state_mutability":"external"}]},{"name":"constructor","type":"constructor","inputs":[{"name":"recipient","type":"core::starknet::contract_address::ContractAddress"},{"name":"base_uri","type":"core::felt252"}]},{"kind":"struct","name":"achievments::contract::contract::Transfer","type":"event","members":[{"kind":"key","name":"from","type":"core::starknet::contract_address::ContractAddress"},{"kind":"key","name":"to","type":"core::starknet::contract_address::ContractAddress"},{"kind":"key","name":"token_id","type":"core::integer::u256"}]},{"kind":"struct","name":"achievments::contract::contract::Approval","type":"event","members":[{"kind":"key","name":"owner","type":"core::starknet::contract_address::ContractAddress"},{"kind":"key","name":"approved","type":"core::starknet::contract_address::ContractAddress"},{"kind":"key","name":"token_id","type":"core::integer::u256"}]},{"kind":"struct","name":"achievments::contract::contract::ApprovalForAll","type":"event","members":[{"kind":"key","name":"owner","type":"core::starknet::contract_address::ContractAddress"},{"kind":"key","name":"operator","type":"core::starknet::contract_address::ContractAddress"},{"kind":"data","name":"approved","type":"core::bool"}]},{"kind":"enum","name":"achievments::contract::contract::Event","type":"event","variants":[{"kind":"nested","name":"Transfer","type":"achievments::contract::contract::Transfer"},{"kind":"nested","name":"Approval","type":"achievments::contract::contract::Approval"},{"kind":"nested","name":"ApprovalForAll","type":"achievments::contract::contract::ApprovalForAll"}]}]



    async def create_tnx_for_mint(self, sender: BaseStarkAccount, eth: Token):
        contract_address = random.choice(self.contracts)

        contract = Contract(contract_address, self.ABI, sender.stark_native_account, cairo_version=1)
        price = (await handle_dangerous_request(contract.functions["get_price"].call, "can't get NFT price. Error", sender.formatted_hex_address))[0]
        call1 = eth.get_approve_call_wei(price, contract_address, sender)

        call2 = contract.functions["mint"].prepare()

        return [call1, call2]
    

async def main():
    stars_hand = StarkStars()
    eth = Token("ETH", 0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7, 18)
    
    with open("keys.txt", "r") as f:
        keys = f.read().split("\n")
    accounts = []
    for key in keys:
        stark_native_account, call_data, salt, class_hash = import_stark_account(int(key, 16))
        accounts.append(StarkAccount(stark_native_account, call_data, salt, class_hash))
    
    for account in accounts:
        for i in range(random.randint(*mint_amount)):
            logger.info(f"[{account.formatted_hex_address}] going to mint starkstars nft")
            calldata = await stars_hand.create_tnx_for_mint(account, eth)
            await account.send_txn(calldata)
            await sleeping(account.formatted_hex_address)
        await asyncio.sleep(*AccountDelay)


if __name__ == "__main__":
    asyncio.run(main())