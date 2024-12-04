# PRIMARY REPORT ON THE MATCHAIN ECOSYSTEM #

This report aims to do a primary analysis of the Matchain ecosystem, covering a wide spectrum of topics such as teh core and periphery contracts, the network capabilities and user engagement, as well as considerations regarding the ecosystem's health and steps to be taken to improve it going forward.

As such the report will be split into two parts - the first part will be the code part, and the second one will be mostly focused on OSINT and concerns regarding the the blockchain itself as well as the ecosystem it supports.

## Part 1: Code Analysis ##

The emphasis for this primary analysis was given on the contracts mentioned in the developer docs of Matchain's official website (https://docs.matchain.io/development/contracts). All of the contracts were cloned and analyzed locally using Foundry on VsCode against the most prominent attack vectors and vulnerabilities DeFi contracts are systematically exposed to as of Dec 24. 

The following list of contracts comprise the infrastracture of the Matchain ecosystem: 


- AddressManager    
- AnchorStateRegistry  
- AnchorStateRegistryProxy  
- DelayedWETH
- DelayedWETHProxy
- DisputeGameFactory
- DisputeGameFactoryProxy
- L1CrossDomainMessenger
- L1CrossDomainMessengerProxy
- L1ERC721Bridge
- L1ERC721BridgeProxy
- L1StandardBridge
- L1StandardBridgeProxy
- L2OutputOracle
- L2OutputOracleProxy
- Mips
- OptimismMintableERC20Factory
- OptimismMintableERC20FactoryProxy
- OptimismPortal
- OptimismPortal2
- OptimismPortalProxy
- PreimageOracle
- ProtocolVersions
- ProtocolVersionsProxy
- ProxyAdmin
- SafeProxyFactory
- SafeSingleton
- SuperchainConfig
- SuperchainConfigProxy
- SystemConfig
- SystemConfigProxy
- SystemOwnerSafe

The analysis was conducted using Foundry and apart from the manual analysis, fuzzing and static analysis tools were also employed. Aderyn, Slither and Echidna were used to analyze the contracts for vulnerabilities and potential attack vectors.
However, most of these contracts are not proprietary and are based on OpenZeppelin contracts, which are widely used and tested. These contracts comprise the infrastrucure contracts of a myriad of protocols, facilitating the passing of messages between L1
and L2 layers, the generation of Mintable ERC20 contracts and the outputs contracts like the OptimismPortal use to verify information about the state of L2. Hence, these contracts are well-audited and battle-tested against vulnerabilities. So focus had to be given on `SuperchainConfig` which is specific to the ecosystem and is still unaudited. 

Focusing on the `SuperchainConfig`, we managed to find some low level vulnerabilities and we have some recommendations regarding enhancing its robustness as follows:

### [L-1] The Guardian role can only be updated through an update 
**Description**

The Guardian role can only be changed via an upgrade, which can limit flexibility in emergency scenarios.

- Current Design
  
The guardian address is stored in the `GUARDIAN_SLOT` and is set during initialization using the `_setGuardian` internal function.
Once set, the guardian address is immutable unless the contract is upgraded. This ensures that the guardian's power is static, reducing attack vectors related to dynamic privilege escalation.

- Potential Issue

If the guardian address becomes compromised or if the organization’s structure changes, there is no way to update the guardian address without upgrading the entire contract. Contract upgrades can be expensive, complex, and time-consuming, making them less ideal for emergency situations.

- Emergency Risk

If the guardian loses access to their private key or the guardian’s address is unintentionally set to an incorrect value, the system could become permanently paused or unmanageable.


**Recommended mitigation**

Consider adding a MultiSig for Guardian privileges. MultiSig wallets like Gnosis Safe require multiple approvals to execute transactions, eliminating the risks of single points of failure. 

```javascript
address public guardian;

function isGuardian(address _address) public view returns (bool) {
    return MultisigWallet(guardian).isOwner(_address);
}
```

another approach would be to introduce a backup mechanism in case of emergencies that will take over.
    
```javascript
address public secondaryGuardian;

modifier onlyGuardianOrSecondaryGuardian() {
    require(msg.sender == guardian() || msg.sender == secondaryGuardian, "Unauthorized");
    _;
}

function setSecondaryGuardian(address _secondaryGuardian) external onlyGuardian {
    require(_secondaryGuardian != address(0), "Backup guardian is address(0)!");
    secondaryGuardian = _secondaryGuardian;
}
```

lastly, a governance controlled mechanism could be implemented instead.

```javascript
function setGuardian(address _guardian) external {
    require(msg.sender == address(governance), "Only governance");
    _setGuardian(_guardian);
}
```

### [L-2] Lack of Input validation in `initialize` function
**Description**

No validation is performed on the _guardian address (ensuring for instance that it’s not address(0)).

**Recommended mitigation**

Add input validation to the `initialize` function to ensure that the _guardian address is not address(0).

```javascript
function initialize(address _guardian, bool _paused) public initializer {
    require(_guardian != address(0), "SuperchainConfig: guardian cannot be zero address");
    _setGuardian(_guardian);
    if (_paused) {
        _pause("Initializer paused");
    }
}
```

## Utility contracts

Moving on to the most concerning part of the code analysis, emphasis was given on the utility contracts, mainly the MSwap protocol, a decentralized exchange platform enabling efficient token swaps which is a direct fork of Uniswap V2. Although being a staple in the DeFi ecosystem, Uniswap V2 has been the target of numerous attacks and exploits, and recommendations had to be given to switch to a more secure version of the protocol, such as a fork Uniswap V3, which has been designed with security in mind and has a more robust architecture.

Essentially, as this is a relatively new ecosystem boasting robust, modernized tech, it would be expected that a newer, more robust model would be used to allow new users more flexibility and options while also being safer, despite the potentialy steeper learning curve. The challenges Uniswap v2 faced will be prevalent here too as an influx of builders and token could be expected to surge in this newer ecosystem, and blackhats will be on the hunt for exploits against the MSwap protocol as soon as there is more building in the chain. Price oracle manipulation, flash loan attacks, impermanent loss, high slippage for large trades, liquidity fragmentation and passive LP strategies are all issues that a migration to a more robust protocol would address.

### Price Oracle Manipulation

Time-weighted average prices (TWAPs) like the ones used in Uniswap V3 can be introduced to make price manipulation harder by requiring changes to persist over several blocks. A function like `observe` can aggregate cumulative tick values over time, making it challenging to manipulate prices within a single block.

```javascript
// In UniswapV3Pool.sol
function observe(uint32[] calldata secondsAgos)
    external
    view
    returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s)
{
    // Uses cumulative ticks to compute TWAP over desired periods
    return observations.observe(secondsAgos, slot0, liquidity, block.timestamp);
}
```

### Flash Loan Attacks

Similar to above, time-weighted oracles can mitigate the impact of flash loans by requiring persistent manipulation over multiple blocks. Users are, and must be encouraged to fetch prices using TWAPs. This way, by using historical tick data, oracles derive prices resistant to short-term manipulations making flash loan attacks ineffective.

```javascript
function consult(address pool, uint32 secondsAgo) external view returns (uint256 price) {
    // Observing TWAP data for realistic price in uni v3
    (int56[] memory tickCumulatives,) = IUniswapV3Pool(pool).observe([secondsAgo, 0]);
    int56 tickDelta = tickCumulatives[1] - tickCumulatives[0];
    return TickMath.getSqrtRatioAtTick(tickDelta / secondsAgo);
}
```

### Impermanent Loss

What separated V3 from V2 most, was the introduction of the concept of concentrated liquidity which allowed LPs to define ranges and enabling them to focus liquidity where it is most needed. This improves fee capture relative to impermanent loss.
Utilizing something like Uni's tickLower and tickUpper, will concentrate liquidity and minimize exposure to impermanent loss outside their selected range.

```javascript
// This can be found in UniswapV3Pool.sol
function mint(
    address recipient,
    int24 tickLower,
    int24 tickUpper,
    uint128 amount,
    bytes calldata data
) external override returns (uint256 amount0, uint256 amount1) {
    // LPs specify a price range for their liquidity
    // Concentrated liquidity reduces impermanent loss risk
    Position storage position = positions.get(recipient, tickLower, tickUpper);
    uint256 amount0Added;
    uint256 amount1Added;
    (amount0Added, amount1Added) = modifyPosition(recipient, tickLower, tickUpper, int256(amount));
    emit Mint(msg.sender, recipient, tickLower, tickUpper, amount, amount0Added, amount1Added);
    return (amount0Added, amount1Added);
}
```

### High Slippage for Large Trades

Introducing a concept like concentrated liquidity also enables deeper liquidity in specific ranges, reducing slippage for trades executed within those ranges.

```javascript
// Also found in UniswapV3Pool.sol
function swap(
    address recipient,
    bool zeroForOne,
    int256 amountSpecified,
    uint160 sqrtPriceLimitX96,
    bytes calldata data
) external override returns (int256 amount0, int256 amount1) {
    // Swap logic within concentrated liquidity ranges
    Slot0 memory slot0Start = slot0;
    (amount0, amount1) = SwapMath.computeSwapStep(
        slot0Start.sqrtPriceX96,
        sqrtPriceLimitX96,
        liquidity,
        amountSpecified,
        fee
    );
    emit Swap(msg.sender, recipient, amount0, amount1, slot0.sqrtPriceX96, liquidity, fee);
    return (amount0, amount1);
}
```

### Liquidity Fragmentation

Introducing structs like `position` will allow LPs to target specific ranges, ensuring liquidity is used where it’s most needed instead of being evenly distributed like in MSwap.

```javascript
// In Position.sol
struct Position {
    uint128 liquidity;
    uint256 feeGrowthInside0LastX128;
    uint256 feeGrowthInside1LastX128;
    uint128 tokensOwed0;
    uint128 tokensOwed1;
}
// LPs can define a position with specified liquidity within a range of ticks
```

### Passive LP Strategies

LPs will actively manage their positions and optimize their fees by adjusting their ranges as market conditions change.

```javascript
// In UniswapV3Pool.sol
function burn(
    int24 tickLower,
    int24 tickUpper,
    uint128 amount
) external override returns (uint256 amount0, uint256 amount1) {
    // Allows LPs to withdraw specific portions of liquidity
    Position storage position = positions.get(msg.sender, tickLower, tickUpper);
    uint256 amount0Burned;
    uint256 amount1Burned;
    (amount0Burned, amount1Burned) = modifyPosition(msg.sender, tickLower, tickUpper, -int256(amount));
    emit Burn(msg.sender, tickLower, tickUpper, amount, amount0Burned, amount1Burned);
    return (amount0Burned, amount1Burned);
}
```

## Matchain Repo on Github 

The Matchain repo on Github (https://github.com/matchain) was next in scope. It consists of 13 repositories, most of which are direct forks of other projects. Similarly to the first section of the assessment, these are truly tested and widely used, and they are trusted codebases to build on. No security concerns arose.




## Part 2: OSINT and Ecosystem Health ##

The second part of the report will focus on the OSINT and concerns regarding the blockchain itself as well as the ecosystem it supports. Research was carried out online as far as Matchain and partners are concerned, and Twitter/Discord accounts were made to inquire about problems faced and to confront the teams and devs on issues that surfaced while doing research.

### MatchID

MatchID is a decentralized identity (DID) solution developed by Matchain to empower users with full control over their digital identities and personal data. It facilitates seamless access across various platforms and blockchains, enabling users to manage their identities securely and efficiently.

- User Data Sovereignty: MatchID ensures that users have complete ownership of their data. Any sharing of personal information requires explicit user consent, and users receive a share of the revenue generated from their data, promoting transparency and fairness. 
- Interoperability: Designed to be compatible with both Ethereum Virtual Machine (EVM) and MOVE, MatchID offers full interoperability across multiple blockchains. Its white-labeled SDK allows for seamless integration into any protocol within approximately 10 minutes. 
- Enhanced Security: Utilizing advanced technologies such as zero-knowledge proofs and homomorphic encryption, MatchID ensures that user identities and data remain private and secure, protecting against unauthorized access and breaches. 
- Simplified Onboarding: MatchID provides a low-threshold DID registration system that effortlessly imports Web2 users, bridging interactions across multiple blockchains and simplifying the transition to decentralized platforms. 
- By adopting MatchID, users can embrace digital autonomy, controlling and benefiting from their digital identities while interacting seamlessly across various decentralized applications (dApps) and platforms.


However, despite this being advertised as the most cutting-edge tool at a user's disposal when it comes to Matchain, it is still unclear how it will actually work as it is still unlaunched as of now and the link to create the MatchId on the official website is not working. Additionally, there is no clear documentation on the tech behind it and the way it will be implemented. This is a major concern as the main selling point that would differentiate the chain to others is yet to be viable. Lastly, it is mentioned that there will be need for only one set of credentials across web2 and web3 platforms which may sound attractive to the general public, but it introduces a single point of failure and a potential security risk, especially at this point when there is no clear documentation on how the system will work.

### User engagement

The user engagement on the Matchain ecosystem right now is relatively centered around Don't FOMO (https://fomogame.org/) a mini-game that will be launching soon, and World Of Dypians a metaverse game that has partnered with Matchain. More DeFi-related engagement seems to be stale and less attention seems to have been given in partnerships for more serious real world applications like Real World Assets. For instance, on the ecosystem page of Matchain (https://matchain.io/ecosystem) there is mention of RAW under DeFi partnerships but if you visit RWA's corresponding page (https://www.rwa.inc/partners) there is no mention of Matchain. This might seem like a simple oversight, but to the trained professional it could mean lack of professionalism when it comes to partnership deals and could be a red flag for potential investors.

### Wallets, NFTs, Tokens 

Analyzing the user interactions on Matchain's discord, it is clear that there are technical problems when it comes to the above. Users cannot mint their NFTs, they cannot see tokens of the chains they have previously claimed and other technical problems. The only response from the team was that it "works just fine for some devices" which is not a professional response. This is a major concern as it shows that the team is not able to handle the technical problems, eroding user trust.

### Documentation on the native token

$MAT, the native token of Matchain (not launched yet, no TGE announced) lacks explicit documentation page on the official website. There is no clear explanation on the tokenomics, and some of the functionality/utility it will bring to the ecosystem was given by a Discord operator only after inquiring repeatedly. Upon further inquiry about the documentation, the response was that there is none included for non-disclosure reasons. This is another deterrent to potential investors as there is no clear path to what they need to expect.

### Network Issues

In the last 3 months there have been 14 issues regarding the block explorer. Users and dApps relying on the Explorer API may have been unable to retrieve transaction or block data. Transactions themselves go unaffected, as the downtime only impacts visibility, not the underlying blockchain network. However, server overloads, configuration errors, and disruptions in infrastructure can lead to erosion of trust in the network, driving away users. Using tools to btter monitor API health may keep the team more alert to issues, leading to shorter downtimes.

2 issues were also reported regarding the rollup system. Namely the one on September 10th, when Matchain's monitoring system detected a significant discrepancy between the l2_safe and l2_unsafe block numbers, with a difference of 5,689 blocks—exceeding the threshold of 5,400 blocks. This discrepancy suggested a potential issue with the proposer component of the rollup system. 

l2_safe: Represents the latest block that has been fully validated and is considered secure within the Layer 2 (L2) rollup.
l2_unsafe: Denotes the most recent block that has been proposed but not yet fully validated.
Under normal conditions, the difference between l2_safe and l2_unsafe is minimal, indicating that new blocks are quickly validated and secured. However, a substantial gap, such as the 5,689-block difference observed, indicates that new blocks are being proposed but not promptly validated, leading to potential delays in transaction finality and network instability.

It could have been caused by a variety of factors, such as slow validation times, proposer malfunction, network congestion, faulty synchronization or even external attacks.

Its Portential impact was as follows:

- Delayed Transaction Finality: Users may experience delays in the confirmation of their transactions, as blocks remain in an unvalidated state longer than usual.
- Network Instability: A prolonged discrepancy can lead to uncertainties about the state of the blockchain, affecting dApps and services relying on timely data.
Resolution:

The issue was resolved within 44 minutes, by 6:56 AM UTC, restoring normal synchronization between proposed and validated blocks. 

Possible mitigations to future incidents include:

- Robust Monitoring:
Continuously monitor proposer performance and proof finalization.
- Redundancy:
Deploy multiple proposers and provers to ensure failover capabilities.
- Stress Testing:
Simulate high loads and failure scenarios to identify weaknesses.
- Scalability Enhancements:
Optimize gas usage and improve interaction with Layer 1 to handle congestion better.

### Tokens built on Matchain

Visiting the token page of Matchain (https://matchscan.io/tokens) it is clear that the vast majority of tokens built by aspiring devs on the chain follow the trend of other chains like Solana, in which meme tokens instead of real utility tokens are built, provoking distruct and eroding trust in the capabilities of the chain which are actually far greater. As this is a relatively younger chain, and even though the trend is expected, more robust, useful tokens are needed to attract more serious investors and devs to the chain. Tokens that will provide utility and real world value. The marketing teams should be advised to shift the paradigm from meme tokens to real world utility tokens and promote/encourage the building of such tokens as that would make the chain more attractive and serious to the general public. A simple search on Eth vs Sol would verify this claim, as to which chain is taken more seriously when it comes to protocols with large TVLs.

### Social Media Presence

After creating two different accounts on both Twitter and Discord one as a dev and one as an aspiring investor, and asking several questions, I was bombarded by trolls and fake support channels trying to scam me. Even though this was to be expected, the amount of time it took for moderators to ban these accounts from the server or delete their misguiding messages from Discord's public channels was concerningly long. The teams need to be instructed to be more vigilant as more naive and inexperienced users of the chain are bound to be targeted and attacked. This should not be happening in public, and not for this kind of duration, otherwise there will be loss of trust in the chain and user engagement will drop.

## Conclusion

The Matchain ecosystem is a promising chain with a lot of potential, but there are several concerns that I would like to see addressed in order to facilitate long-term success. The codebase is solid and well-audited, but there is room for much improvement in certain areas. The lack of documentation on the MatchID and the native token is also a concern, as it makes it difficult for potential investors to understand the value proposition of the ecosystem. The user engagement on the chain is also lacking, with technical issues and network problems causing frustration among users. The team needs to be more vigilant in monitoring the network and responding to user concerns in a timely manner. Overall, the Matchain ecosystem has a lot of potential, but there are several areas that need to be improved in order to ensure its long-term success.



