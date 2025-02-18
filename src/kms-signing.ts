import {
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
  SignCommandInput,
  SignCommandOutput,
} from '@aws-sdk/client-kms'
// @ts-ignore
import * as ethutil from 'ethereumjs-util'
import * as asn1 from 'asn1.js'
import BN from 'bn.js'
import { FeeMarketEIP1559Transaction, Transaction } from '@ethereumjs/tx'
import { Common } from '@ethereumjs/common'
import { keccak256 } from '@ethersproject/keccak256'
import {
  BigNumber,
  BigNumberish,
  PopulatedTransaction,
  providers,
} from 'ethers'
import { BobaChains, IKMSSignerConfig } from '@bobanetwork/light-bridge-chains'

export class KMSSigner {
  private kmsClient: KMSClient
  private readonly kmsKeyId: string

  constructor(kmsSignerConfig: IKMSSignerConfig, isDevelopment = true) {
    const {
      awsKmsEndpoint,
      awsKmsKeyId,
      awsKmsRegion,
      awsKmsSecretKey,
      awsKmsAccessKey,
      awsKmsSessionToken,
    } = kmsSignerConfig
    if (isDevelopment) {
      this.kmsClient = new KMSClient({
        region: awsKmsRegion,
        endpoint: awsKmsEndpoint,
        credentials: {
          accessKeyId: awsKmsAccessKey, // credentials for your IAM user with KMS access
          secretAccessKey: awsKmsSecretKey, // credentials for your IAM user with KMS access
          sessionToken: awsKmsSessionToken,
        },
      })
    } else {
      this.kmsClient = new KMSClient({
        region: awsKmsRegion,
      })
    }

    this.kmsKeyId = awsKmsKeyId
  }

  private EcdsaSigAsnParse = asn1.define('EcdsaSig', function (this: any) {
    // parsing this according to https://tools.ietf.org/html/rfc3279#section-2.2.3
    this.seq().obj(this.key('r').int(), this.key('s').int())
  })

  private EcdsaPubKey = asn1.define('EcdsaPubKey', function (this: any) {
    // parsing this according to https://tools.ietf.org/html/rfc5480#section-2
    this.seq().obj(
      this.key('algo').seq().obj(this.key('a').objid(), this.key('b').objid()),
      this.key('pubKey').bitstr()
    )
  })

  private sign = (
    msgHash: Uint8Array | undefined
  ): Promise<SignCommandOutput> => {
    const params: SignCommandInput = {
      // key id or 'Alias/<alias>'
      KeyId: this.kmsKeyId,
      Message: msgHash,
      // 'ECDSA_SHA_256' is the one compatible with ECC_SECG_P256K1.
      SigningAlgorithm: 'ECDSA_SHA_256',
      MessageType: 'DIGEST',
    }
    return this.kmsClient.send(new SignCommand(params))
  }

  private getPublicKey = (keyPairId: string) => {
    return this.kmsClient.send(new GetPublicKeyCommand({ KeyId: keyPairId }))
  }

  private getEthereumAddress = (publicKey: Buffer): string => {
    // The public key is ASN1 encoded in a format according to
    // https://tools.ietf.org/html/rfc5480#section-2
    // I used https://lapo.it/asn1js to figure out how to parse this
    // and defined the schema in the EcdsaPubKey object
    const res = this.EcdsaPubKey.decode(publicKey, 'der')
    let pubKeyBuffer: Buffer = res.pubKey.data

    // The public key starts with a 0x04 prefix that needs to be removed
    // more info: https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
    pubKeyBuffer = pubKeyBuffer.subarray(1, pubKeyBuffer.length)

    const address = keccak256(pubKeyBuffer) // keccak256 hash of publicKey
    const ethAddr = `0x${address.substring(address.length - 40)}`
    return ethAddr
  }

  private findEthereumSig = async (msgHash) => {
    const signature = await this.sign(msgHash)
    if (signature.Signature === undefined) {
      throw new Error('Signature is undefined.')
    }
    const sigBuffer: Buffer = Buffer.from(signature.Signature)

    const decoded = this.EcdsaSigAsnParse.decode(sigBuffer, 'der')
    const r: BN = decoded.r
    let s: BN = decoded.s

    const tempsig = r.toString(16) + s.toString(16)

    const secp256k1N = new BN(
      'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
      16
    ) // max value on the curve
    const secp256k1halfN = secp256k1N.div(new BN(2)) // half of the curve
    // Because of EIP-2 not all elliptic curve signatures are accepted
    // the value of s needs to be SMALLER than half of the curve
    // i.e. we need to flip s if it's greater than half of the curve
    if (s.gt(secp256k1halfN)) {
      // According to EIP2 https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
      // if s < half the curve we need to invert it
      // s = curve.n - s
      s = secp256k1N.sub(s)
      return { r, s }
    }
    // if s is less than half of the curve, we're on the "good" side of the curve, we can just return
    return { r, s }
  }

  private recoverPubKeyFromSig = (msg: Buffer, r: BN, s: BN, v: number) => {
    const rBuffer = r.toBuffer()
    const sBuffer = s.toBuffer()
    const pubKey = ethutil.ecrecover(msg, v, rBuffer, sBuffer)
    const addrBuf = ethutil.pubToAddress(pubKey)
    return ethutil.bufferToHex(addrBuf)
  }

  private findRightKey = (
    msg: Buffer,
    r: BN,
    s: BN,
    expectedEthAddr: string,
    isEIP1559: boolean
  ) => {
    // This is the wrapper function to find the right v value
    // There are two matching signatues on the elliptic curve
    // we need to find the one that matches to our public key
    // it can be v = 27 or v = 28

    let leftSide = true
    let v = isEIP1559 ? 0 : 27 /* +0 */
    let pubKey = this.recoverPubKeyFromSig(msg, r, s, v)
    if (pubKey !== expectedEthAddr) {
      // if the pub key for v = 27 does not match
      // it has to be v = 28
      v = isEIP1559 ? 1 : 28
      pubKey = this.recoverPubKeyFromSig(msg, r, s, v)
      leftSide = false // on the curve
    }
    console.log('sendRawTx: V-param -> ', v, 'IsEIP1559: ', isEIP1559)

    return { pubKey, v, leftSide }
  }

  public getSignerAddr = async () => {
    const pubKey = await this.getPublicKey(this.kmsKeyId)
    return this.getEthereumAddress(Buffer.from(pubKey.PublicKey))
  }

  public sendTxViaKMS = async (
    providerUrl: string | providers.Provider,
    contractAddr: string,
    nativeValue: BigNumber,
    unsignedTx: PopulatedTransaction
  ) => {
    const provider =
      typeof providerUrl === 'string'
        ? new providers.JsonRpcProvider(providerUrl)
        : providerUrl

    // if defined, then supports 1559
    const feeDataGasPrice = await provider.getFeeData()
    const supportsEIP1559 = !!feeDataGasPrice?.maxFeePerGas // (BNB e.g. does support it, but library says not)

    const chainId = (await provider.getNetwork()).chainId

    const ethAddr = await this.getSignerAddr()
    const ethAddrHash = ethutil.keccak(Buffer.from(ethAddr))
    const sig = await this.findEthereumSig(ethAddrHash)
    const recoveredPubAddr = this.findRightKey(
      ethAddrHash,
      sig.r,
      sig.s,
      ethAddr,
      supportsEIP1559
    )
    console.log(
      `Recovered disburser: ${recoveredPubAddr?.pubKey}, ${recoveredPubAddr.v}`
    )
    // pre: 27 +0/1 without replay protection
    const parity = recoveredPubAddr.leftSide ? 0 : 1
    const vEIP155 = chainId * 2 + 35 + parity
    const v = new BN(supportsEIP1559 ? recoveredPubAddr.v : vEIP155).toBuffer()

    let baseTxObj = {
      nonce: await provider.getTransactionCount(ethAddr),
      gasLimit: 10_000_000,
      to: contractAddr,
      r: sig.r.toBuffer(),
      s: sig.s.toBuffer(),
      v,
      value: nativeValue.toHexString(),
      data: Buffer.from(unsignedTx.data.slice('0x'.length), 'hex'),
    }

    console.log(`Building disbursementTx..`, chainId, baseTxObj?.nonce)
    let tx: Transaction | FeeMarketEIP1559Transaction

    let common: Common
    if (Common.isSupportedChainId(BigInt(chainId))) {
      common = new Common({ chain: chainId })
    } else {
      const chain =
        BobaChains[chainId] ??
        {
          31337: { name: 'Localhost:eth', networkId: 31337, chainId: 31337 },
          31338: { name: 'Localhost:bnb', networkId: 31338, chainId: 31338 },
        }[chainId]
      if (!chain) {
        throw new Error(
          'Unsupported chainId and could not find network config in BobaChains: ' +
            chainId
        )
      }
      common = Common.custom({
        name: chain.name,
        chainId: chainId,
        networkId: chainId,
      })
    }

    if (supportsEIP1559) {
      tx = new FeeMarketEIP1559Transaction(
        {
          ...baseTxObj,
          chainId,
          // gasPrice prop must be undefined
          maxFeePerGas: feeDataGasPrice.maxFeePerGas.toHexString(),
          maxPriorityFeePerGas:
            feeDataGasPrice.maxPriorityFeePerGas.toHexString(),
          type: '0x02',
        },
        { common }
      )
    } else {
      let gasPrice: BigNumberish = (await provider.getGasPrice())
        .mul('150')
        .div('100')

      if (feeDataGasPrice.gasPrice.gt(gasPrice)) {
        gasPrice = feeDataGasPrice.gasPrice
      }
      gasPrice = gasPrice.toHexString()

      common.setHardfork('berlin')
      tx = new Transaction(
        {
          ...baseTxObj,
          gasPrice,
        },
        { common }
      )
    }

    return this.sendRawTx(chainId, ethAddr, provider, tx, supportsEIP1559)
  }

  private sendRawTxWithTimeout = async (provider: providers.Provider, serializedTx: string) => {
    const timeoutMs = 120_000 // 120 seconds
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Transaction send timeout')), timeoutMs)
    })

    try {
      const sendPromise = provider.sendTransaction(`0x${serializedTx}`)
      const response: any = await Promise.race([sendPromise, timeoutPromise])

      // Validate response
      if (!response || !response.hash) {
        throw new Error('Invalid transaction response')
      }

      await provider.waitForTransaction(response.hash)

      // Verify transaction was actually submitted
      const txCheck = await provider.getTransaction(response.hash)
      if (!txCheck) {
        throw new Error('Transaction not found after submission')
      }

      return response
    } catch (error) {
      // Check for specific provider errors
      if (error.code === 'SERVER_ERROR') {
        throw new Error(`Provider server error: ${error.message}`)
      }
      if (error.code === 'TIMEOUT') {
        throw new Error('Provider timeout')
      }
      if (error.code === 'NETWORK_ERROR') {
        throw new Error('Provider network error')
      }

      // Rate limiting detection
      if (error.message?.includes('rate') || error.message?.includes('limit')) {
        throw new Error('Provider rate limit exceeded')
      }

      // RPC specific errors
      if (error.code === -32000) { // Generic RPC error
        throw new Error(`RPC error: ${error.message}`)
      }
      if (error.code === -32601) { // Method not found
        throw new Error('RPC method not supported by provider')
      }
      if (error.code === -32602) { // Invalid params
        throw new Error('Invalid transaction parameters')
      }

      throw error
    }
  }


  private sendRawTx = async (
    chainId: number,
    ethAddr: string,
    provider: providers.Provider,
    tx: Transaction | FeeMarketEIP1559Transaction,
    supportsEIP1559: boolean
  ) => {
    const signedTx = await this.getSignedKmsTx(chainId, tx, supportsEIP1559)

    // Send signed tx to ethereum network
    const serializedTx = signedTx.serialize().toString('hex')
    return this.sendRawTxWithTimeout(provider, serializedTx)
  }


  public getSignedKmsTx = async (
      chainId: number,
      tx: Transaction | FeeMarketEIP1559Transaction,
      supportsEIP1559: boolean
  ): Promise<Transaction | FeeMarketEIP1559Transaction> => {
    const ethAddr = await this.getSignerAddr()
    const msgHash = tx.getMessageToSign(true) // tx.hash();
    const sig = await this.findEthereumSig(msgHash)

    const recoveredPubAddr = this.findRightKey(
        msgHash,
        sig.r,
        sig.s,
        ethAddr,
        supportsEIP1559
    )

    const r = sig.r.toBuffer()
    const s = sig.s.toBuffer()

    // pre: 27 +0/1 without replay protection
    const parity = recoveredPubAddr.leftSide ? 0 : 1
    const vEIP155 = chainId * 2 + 35 + parity
    const v = new BN(supportsEIP1559 ? recoveredPubAddr.v : vEIP155).toBuffer()

    console.log(`Sending raw KMS tx..`, recoveredPubAddr.pubKey)
    console.log(`Overriden parity (v): `, vEIP155, parity, recoveredPubAddr.v)

    const signedTx: Transaction | FeeMarketEIP1559Transaction = supportsEIP1559
        ? new FeeMarketEIP1559Transaction({
          ...(tx as FeeMarketEIP1559Transaction),
          r,
          s,
          v,
        })
        : new Transaction({ ...(tx as Transaction), r, s, v })

    const senderAddr: string = signedTx
        .getSenderAddress()
        .toBuffer()
        .toString('hex')

    console.log(
        `Checking sender address for KMS disburser: `,
        senderAddr,
        recoveredPubAddr?.pubKey
    )
    if (`0x${senderAddr}` !== recoveredPubAddr.pubKey) {
      throw new Error(
          'Signature invalid, recovered this sender address: ' + senderAddr
      )
    }
    return signedTx
  }

}
