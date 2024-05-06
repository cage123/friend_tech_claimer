from web3 import Web3
import requests
from random import randint, shuffle
import time
from datetime import datetime
from eth_account.messages import encode_defunct
import pyuseragents
import sys
import uuid

from data import *
from inputs.config import *

class FriendTech:
    def __init__(self, key, proxy) -> None:
        self.privatekey = key
        self.proxy = proxy
        self.ft_signature = ''
        self.ft_auth = ''
        self.uuid = uuid.uuid4()

        self.w3 = Web3(Web3.HTTPProvider(config['RPC_BASE']))
        self.account = self.w3.eth.account.from_key(self.privatekey)
        self.address = self.account.address
        
        self.CAPTCHA_KEY = config['CAPTCHA_KEY']
        self.session = requests.Session()
        self.proxies = {'http': f'http://{self.proxy}', 'https': f'http://{self.proxy}'} if self.proxy and self.proxy != '' else {}
        self.session.proxies.update(self.proxies)

    def claim_second(self):
        for i in range(5):
            try:
                proof = self.get_claim_proof()
                _proof = []
                for item in proof["claim2Proof"]:
                    _proof.append(item[2:])
            except Exception:
                time.sleep(5)
        
        proof_length = len(_proof)
        amount = f'0000000000000000000000000000000000000000000000000{hex(int(proof["claim2Amount"]))[2:]}'
        tx_data = f'0x1c71f9bc' \
            f'00000000000000000000000000000000000000000000000000000000000000a0' \
            f'000000000000000000000000{config["SEND_TO"][2:]}' \
            f'{amount[-64:]}' \
            f'0000000000000000000000000000000000000000000000000000000000000{hex((proof_length + 6) * 32)[2:]}' \
            f'0000000000000000000000000000000000000000000000000000000000000000' \
            f'00000000000000000000000000000000000000000000000000000000000000{hex(proof_length)[2:]}'
        
        for item in _proof:
            tx_data += str(item)
        tx_data += '0000000000000000000000000000000000000000000000000000000000000000'
        
        tx = {
            'to': self.w3.to_checksum_address(data['FT_CLAIM']['contract']),
            'value': 0,
            'data': self.w3.to_bytes(hexstr=tx_data),
        }

        self.send_tx(tx, 'CLAIM_2')

    def random_follow(self):
        to_follow = data['FT_TO_FOLLOW']
        shuffle(to_follow)

        for i in range (15):
            URL = f'https://prod-api.kosetto.com/watchlist-users/{to_follow[i]}'
            headers = {
                'Accept': 'application/json',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Accept-Language': 'ru,en-US;q=0.9,en;q=0.8,vi;q=0.7',
                'Authorization': self.ft_auth,
                'Content-Length': '2',
                'Content-Type': 'application/json',
                'Origin': 'https://www.friend.tech',
                'Priority': 'u=1, i',
                'Referer': 'https://www.friend.tech/',
                'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': "Windows",
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'cross-site',
                'User-Agent': f'{pyuseragents.random()}',
            }

            try:
                self.session.post(URL, headers=headers, json={})
            except Exception as error:
                print(f'Error: {error}')
                time.sleep(1)
                continue

    def create_club(self):
        with open('words.txt', 'r') as file:
            words = file.read().splitlines()
        shuffle(words)
        club_name = f'{words[0]}_{words[1]}_{words[2]}'

        contract = self.w3.eth.contract(self.w3.to_checksum_address(data['FT_CLUB']['contract']), abi=data['FT_CLUB']['abi'])
        tx = contract.functions.createToken(
            club_name,
            '',
            3,
            0,
        ).build_transaction({
            'value': 0,
        })

        self.send_tx(tx, 'CREATE_CLUB')

    def claim_first(self):
        proof = self.get_claim_proof()
        _proof = []
        for item in proof["claim1Proof"]:
            _proof.append(item[2:])
        
        proof_length = len(_proof)
        amount = f'0000000000000000000000000000000000000000000000000{hex(int(proof["claim1Amount"]))[2:]}'
        tx_data = f'0x9d194d18' \
            f'00000000000000000000000000000000000000000000000000000000000000a0' \
            f'000000000000000000000000{config["SEND_TO"][2:]}' \
            f'{amount[-64:]}' \
            f'0000000000000000000000000000000000000000000000000000000000000{hex((proof_length + 6) * 32)[2:]}' \
            f'0000000000000000000000000000000000000000000000000000000000000000' \
            f'00000000000000000000000000000000000000000000000000000000000000{hex(proof_length)[2:]}'
        
        for item in _proof:
            tx_data += item
        tx_data += '0000000000000000000000000000000000000000000000000000000000000000'
        tx = {
            'to': self.w3.to_checksum_address(data['FT_CLAIM']['contract']),
            'value': 0,
            'data': self.w3.to_bytes(hexstr=tx_data),
        }

        self.send_tx(tx, 'CLAIM_1')
    
    def send_tx(self, tx, action_name):
        gasPrice = self.w3.eth.gas_price
        tx['from'] = self.address
        tx['chainId'] = self.w3.eth.chain_id
        tx['nonce'] = self.w3.eth.get_transaction_count(self.address)
        tx['maxFeePerGas'] = int(gasPrice * 1.05)
        tx['maxPriorityFeePerGas'] = int(gasPrice * 1.05)
        tx['gas'] = self.w3.eth.estimate_gas(tx)

        signed_transaction = self.account.sign_transaction(tx)
        txn_hash = self.w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        txn_receipt = self.w3.eth.wait_for_transaction_receipt(txn_hash)
        
        print(f'[{action_name}] | https://basescan.org/tx/{(self.w3.to_hex(txn_hash))}')
        return
    
    def get_claim_proof(self):
        URL = 'https://prod-api.kosetto.com/airdrop'
        headers = {
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'ru,en-US;q=0.9,en;q=0.8,vi;q=0.7',
            'Authorization': f'{self.ft_auth}',
            'Content-Type': 'application/json',
            'Origin': 'https://www.friend.tech',
            'Priority': 'u=1, i',
            'Referer': 'https://www.friend.tech/',
            'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': "Windows",
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'cross-site',
            'User-Agent': f'{pyuseragents.random()}',
        }

        try:
            response = self.session.get(URL, headers=headers)
            if 'totalClaimAmount' in response.text:
                return response.json()
            elif 'User has no claims' in response.text:
                return 'NOT_ELIGIBLE'
            else:
                return 0
                
        except Exception as error:
            print(f'Error: {error}')
            return 0

    def friend_signature(self):
        headers = {
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'ru,en-US;q=0.9,en;q=0.8,vi;q=0.7',
            'Authorization': f'{self.ft_signature}',
            'Content-Length': '56',
            'Content-Type': 'application/json',
            'Origin': 'https://www.friend.tech',
            'Priority': 'u=1, i',
            'Referer': 'https://www.friend.tech/',
            'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': "Windows",
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'cross-site',
            'User-Agent': f'{pyuseragents.random()}',
        }

        try:
            URL = 'https://prod-api.kosetto.com/signature'
            json_data = {
                "address": f"{self.address}",
            }
            
            response = self.session.post(URL, json=json_data, headers=headers)
            if 'Signature verified successfully' in response.text:
                self.ft_auth = response.json()['token']
                
        except Exception as error:
            print(f'Error: {error}')

    def get_signature(self, message_text: str):
        try:
            message = encode_defunct(text=message_text)
            sign = self.w3.eth.account.sign_message(message, private_key=self.privatekey)
            signature = self.w3.to_hex(sign.signature)
            
            return signature
        except Exception as error:
            print(f'Error: {error}')
            return 0

    def friend_auth(self):
        headers = {
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'ru,en-US;q=0.9,en;q=0.8,vi;q=0.7',
            'Content-Length': '627',
            'Content-Type': 'application/json',
            'Origin': 'https://www.friend.tech',
            'Priority': 'u=1, i',
            'Privy-App-Id': 'cll35818200cek208tedmjvqp',
            'Privy-Ca-Id': f'{self.uuid}',
            'Privy-Client': 'react-auth:1.61.0',
            'Referer': 'https://www.friend.tech/',
            'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': "Windows",
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'cross-site',
            'User-Agent': f'{pyuseragents.random()}',
        }

        try:
            _nonce = self.friend_init()['nonce']
            _datetime = datetime.utcnow().isoformat()[:-3]
            _message = f"www.friend.tech wants you to sign in with your Ethereum account:\n{self.address}\n\nBy signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.\n\nURI: https://www.friend.tech\nVersion: 1\nChain ID: 8453\nNonce: {_nonce}\nIssued At: {_datetime}Z\nResources:\n- https://privy.io"
            _signature = self.get_signature(_message)
            
            URL = 'https://auth.privy.io/api/v1/siwe/authenticate'
            json_data = {
                "message": _message,
                "signature": _signature,
                "chainId": "eip155:8453",
                "walletClientType": "metamask",
                "connectorType": "injected",
            }
            
            response = self.session.post(URL, json=json_data, headers=headers)
            if 'refresh_token' in response.text:
                self.ft_signature = response.json()['token']

        except Exception as error:
            print(f'Error: {error}')

    def friend_init(self):
        headers = {
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'ru,en-US;q=0.9,en;q=0.8,vi;q=0.7',
            'Content-Length': '627',
            'Content-Type': 'application/json',
            'Origin': 'https://www.friend.tech',
            'Priority': 'u=1, i',
            'Privy-App-Id': 'cll35818200cek208tedmjvqp',
            'Privy-Ca-Id': f'{self.uuid}',
            'Privy-Client': 'react-auth:1.61.0',
            'Referer': 'https://www.friend.tech/',
            'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': "Windows",
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'cross-site',
            'User-Agent': f'{pyuseragents.random()}',
        }

        try:
            URL = 'https://auth.privy.io/api/v1/siwe/init'
            json_data = {
                "address": f"{self.address}",
                "token": f"{self.get_capcha_response()}",
            }
            
            response = self.session.post(URL, json=json_data, headers=headers)
            if 'nonce' in response.text:
                return response.json()
            else:
                return 0
                
        except Exception as error:
            print(f'Error: {error}')
            return 0

    def get_capcha_response(self):
        URL = 'https://www.friend.tech/'
        json_data = {
            "key": f"{self.CAPTCHA_KEY}",
            "method": "turnstile",
            "sitekey": "0x4AAAAAAAJFhr_rDU7HKpyw",
            "pageurl": f"{URL}",
            "json": 1,
        }

        for i in range(10):
            try:
                response = self.session.post("https://rucaptcha.com/in.php", json=json_data)
                id_ = response.json()["request"]

                while True:
                    response = self.session.get(f"https://rucaptcha.com/res.php?key={self.CAPTCHA_KEY}&action=get&id={id_}")

                    if "OK" in response.text:
                        return response.text.split("|")[1]
                    
                    elif response.text in ("ERROR_CAPTCHA_UNSOLVABLE", "ERROR_WRONG_CAPTHA_ID"):
                        break

                    time.sleep(5)

            except Exception as error:
                print(f'Error: {error}')
                time.sleep(5)
                continue
    
    def check_balance(self) -> bool:
        _balance = self.w3.eth.get_balance(self.w3.to_checksum_address(self.address))
        balance = round(float(self.w3.from_wei(_balance, 'ether')), 8)
        if balance < config['MIN_BALANCE']:
            return False
        else:
            return True
    
    def check_claimed(self) -> bool:
        contract = self.w3.eth.contract(self.w3.to_checksum_address(data['FT_CLAIM']['contract']), abi=data['FT_CLAIM']['abi'])
        status = contract.functions.claimedB(self.address).call()
        return status
    
    def write_result(self, result):
        with open(f'results\{result}.txt', 'a') as file:
            file.write(f'{self.privatekey}\n')
            file.close()

    def main(self, to_print):
        print('\n###-###-###-###-###-###')
        print(f'{to_print} | {self.address}')
        print('###-###-###-###-###-###')
        
        try:
            if (self.check_claimed()):
                print('Already claimed')
                self.write_result('success')
            
            elif (self.check_balance()):
                self.friend_auth()
                self.friend_signature()
                
                proof = self.get_claim_proof()
                if proof == 'NOT_ELIGIBLE':
                    print('Wallet not eligible. Skipping')
                    self.write_result('_not_eligible')
                else:
                    if proof['hasClaimedClaim1']:
                        print('First claim already done!')
                    else:
                        self.claim_first()
                    
                    if not proof['hasFollowedPeople']:
                        self.random_follow()
                    if not proof['hasJoinedClub']:
                        self.create_club()

                    if proof['hasClaimedClaim2']:
                        print('Second claim already done!')
                    else:
                        self.claim_second()
                    
                    self.write_result('success')
            else:
                print(f'Balance lower {config["MIN_BALANCE"]}. Skipping')
                self.write_result('low_balance')
        except Exception as error:
            print(f'Error: {error}')
            self.write_result('error')

if __name__ == '__main__':
    with open('inputs\wallets.txt', 'r') as f:
        wallets = f.read().splitlines()
    with open('inputs\proxies.txt', 'r') as f:
        proxies = f.read().splitlines()
    
    if len(proxies) == 0:
        proxies = [None] * len(wallets)
        print('Прокси отсутствуют!')
    if len(proxies) != len(wallets):
        print('Количество кошельков и прокси не совпадает!')
        sys.exit()
    
    accounts = list(zip(wallets, proxies))
    
    if config['TO_SHUFFLE']:
        shuffle(accounts)
    
    print(f'Wallets count: {len(wallets)}')
    walletID = 1
    for acc in accounts:
        privatekey, proxy = acc
        
        friend = FriendTech(privatekey, proxy)
        friend.main(f'{walletID}/{len(wallets)}')
        walletID += 1

        to_sleep = randint(config['DELAY_ACCS'][0], config['DELAY_ACCS'][1])
        print(f'Sleeping {to_sleep} sec.')
        time.sleep(to_sleep)