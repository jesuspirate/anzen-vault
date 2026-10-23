<p align="center"><img src="media/anzen-banner-v2.svg" alt="Anzen" width="100%"></p>

[![CI](https://github.com/lukechilds/anzen/actions/workflows/ci.yml/badge.svg)](https://github.com/lukechilds/anzen/actions/workflows/ci.yml)

> [!WARNING]
> Anzen is an experimental reference implementation, not a production-ready wallet. The current hardware wallet is simulated in software, mnemonics are printed, and fees are fixed at 1 sat/vB. Use regtest to explore the protocol; do not secure significant mainnet funds with this prototype.

Anzen is a Bitcoin wallet that achieves the two-device compromise resistance of a 2-of-3 multivendor multisig with the simplicity of a mobile hot wallet. It combines a phone hot wallet for everyday use with an independent hardware wallet and a programmable Taproot vault for cold storage.

Most self-custody designs force a compromise: singlesig is simple but makes one key a catastrophic point of failure; multivendor multisig removes that failure but is difficult to operate; collaborative custody restores good UX by introducing a provider with a signing key. Anzen is designed to be secure, easy to use, and trustless at the same time. [Read the motivation behind the design.](https://lu.ke/self-custody-trilemma/)

**The experience of a hot wallet, backed by cold storage.** Think checking and savings: the phone is your checking account and the vault is your savings account. Once a year, the hardware wallet approves a human-readable policy covering a monthly allowance and, optionally, a larger emergency transfer with a one-week cancellation window. It validates and signs the yearly rollover in one ceremony. The rollover sets aside each month's allowance as its own coin with its own unlock date: the phone can spend a month alone once its date has passed, and the hardware wallet can pull any month back at any time.

Immediate vault access requires both independent device keys. If either key is lost or compromised, the honest holder of the other key retains a Bitcoin-enforced route to safety. No company, server, custodian, or online cosigner can change those paths, and losing the presigned policy transactions cannot lose the underlying bitcoin.

Anzen is designed to be difficult to operate incorrectly. It guides complete policy, renewal, revocation, rotation, and recovery operations rather than exposing raw transaction machinery and leaving the user to assemble a safe procedure.

Anzen is an open protocol, and this repository is its reference wallet implementation. Any hardware wallet can implement the cold-wallet side, and any mobile or desktop wallet can implement the hot-wallet side. Compatible implementations can work together without the reference app or any particular vendor.

The [protocol design](anzen-design.md) specifies the exact wallet properties, transaction graph, assumptions, and loss or theft behavior. [Design decisions](design-decisions.md) explains why Anzen uses this model and records its engineering trade-offs.

## How the vault is constructed

Anzen's cold storage is a Taproot address controlled by two keys: the mobile key (`phone`) and the hardware-wallet key (`hww`). Every cold output uses the same vault script. Bitcoin accepts a spend through any one of these paths:

```text
phone + hww immediately
phone only after 14 months
hww only after 15 months
```

The delays belong to each individual UTXO and begin when that output confirms. They are not controlled by Anzen, a server, or a calendar. The earlier phone path gives an honest phone holder a priority window to rotate the vault if the HWW key is stolen.

### Miniscript policy

The policy in minimal Taproot Miniscript descriptor notation is:

```text
tr(
  NUMS,
  {
    multi_a(2,phone,hww),
    {
      and_v(v:older(61200),pk(phone)),
      and_v(v:older(65535),pk(hww))
    }
  }
)
```

Every key is a BIP388 key expression, so a stock hardware wallet (tested with the Ledger Bitcoin app 2.5.1 and BitBox02 firmware 9.26) can register and sign these policies as written:

- `phone` and `hww` are each device's account xpub at `m/86'/coin'/100'/0/index`, with its `[fingerprint/path]` origin.
- `NUMS` is BIP341's point H as an xpub. Every child of H is unspendable. New vaults set its chain code to the SHA256 of the policy's other keys in order, the convention that lets a BitBox02 prove the key is unspendable and label it "Provably unspendable"; Ledger labels it "Dummy key". Vaults made before this change keep chain code `sha256(H)` and their addresses.
- The cooperative leaf and the connector policy use each key at `/<0;1>/*`; the single-key recovery leaves and the allowance-month leaves use `/<2;3>/*`. Ledger refuses a policy that reuses a key with the same derivation in two leaves.
- Anzen uses the receive branch at index 0, so each policy still has one fixed address.

This is Anzen's only long-lived principal-holding script. Each month of the allowance is a separate coin under a dated script, and emergency access uses presigned transactions with Bitcoin-enforced relative timelocks.

An allowance month has its own Taproot address with its own unlock time `T`:

```text
tr(NUMS,{and_v(v:pk(phone),after(T)),pk(hww)})
```

The phone alone can spend the month once `T` has passed; consensus enforces the date through the spending transaction's nLockTime and `OP_CHECKLOCKTIMEVERIFY`. The HWW alone can move the month at any time.

Emergency access keeps its revocable state in separate 1,000-sat connector outputs. They reuse the same device keys under a fixed 1-of-2 Taproot policy:

```text
tr(NUMS,{pk(phone),pk(hww)})
```

Either device can spend a connector alone. The connector does not control vault principal; its exact outpoint is an execution token committed into the presigned emergency PSBTs.

### Annual vault layout

Once per year, the phone proposes a policy and the HWW approves it once. For the allowance, the yearly rollover is the only transaction the HWW signs. It spends the vault and creates, in order: twelve allowance months worth the monthly limit each, at outputs 0 to 11; the remainder back to the vault; and, if emergency access is enabled, the emergency connector. With emergency access the HWW also signs the vault input of the trigger and withdrawal, which stay incomplete and encrypted on the phone until it signs the connector at execution.

![One annual rollover creating twelve dated allowance months, the vault remainder and the emergency connector, for an example 2.1 BTC vault](media/vault-utxo-layout.svg)

The overview shows the state immediately after rollover. Large blue circles are vault UTXOs, violet circles are allowance months, small amber circles are controller-wallet connectors, and boxes are transactions. A dashed outline means that transaction has not happened yet. Round principal amounts are shown so the policy is easy to read; the checked-in test vector contains exact fees and values.

#### Monthly allowance

![Twelve dated allowance months, each claimable by the phone after its date or movable by the HWW at any time](media/monthly-allowance-ladder.svg)

Month `i` unlocks at the ladder start plus `i` × 2,592,256 seconds (about 30 days). The ladder starts at the ceremony time, or later if months from an earlier ceremony are still waiting, so a new ceremony never doubles the monthly limit. The HWW shows every date before it signs, and on networks other than regtest it refuses a proposal whose months start more than a day before its own clock.

Nothing per month is presigned. Every spend of a month is built when it is needed, at that day's fee rate: the phone claims an unlocked month to its hot wallet, the phone returns unclaimed months to the vault, or the HWW pulls months back, locked or not. The HWW keeps its own record of the months it approved (`hww/ladder.json`), so it can pull them back without the phone.

Months are collected in order; skipping one only delays the later ones, and nothing expires. What the phone does not spend can go back to the vault: choose a buffer to keep for bills and emergencies with `anzen phone buffer --set SATS`, and just before a ceremony run `anzen phone return-leftovers`. It sends everything above the buffer to the vault (the fee comes out of the buffer), and once it confirms, the ceremony's rollover folds it into the new months. `phone set-policy` reminds you when the phone holds more than its buffer. Returned coins need two keys again as soon as they land, but they are not part of the current presigned months, which is why the return belongs right before a ceremony.

#### Emergency access

![Emergency access trigger, delayed withdrawal, and connector-only cancellation](media/emergency-access-chain.svg)

The immediate trigger spends the vault remainder and emergency connector, then creates a staged 0.5 BTC vault output, cold change, and the withdrawal connector. After one week, the staged output and connector can be spent together to the hot wallet. Before then, either device can cancel by spending only the withdrawal connector; both principal outputs remain under the vault script and the delayed withdrawal becomes permanently invalid.

Connector change never returns to the controller address: phone cancellation sends it to a fresh hot-wallet change address, while HWW revocation requires an explicitly displayed destination. A later annual rollover spends every live vault and connector output, resets recovery delays, creates only the renewed policy's connector, and invalidates the old emergency transactions. Allowance months that already exist stay at their own addresses until they are claimed, returned or pulled back.

By default one HWW ceremony presigns two years (`phone set-policy --years 2`). The second year's rollover spends the first year's vault remainder and carries a BIP68 delay of 360 days, so it cannot be broadcast early; the HWW checks that link before signing. It creates the second year's twelve months, dated 360 days after the first year's, and a 330-sat fee-bump output paid to a fixed address of the phone's own wallet (rather than a pay-to-anchor output, which no BitBox02 firmware can sign). After the delay, `anzen phone renew` broadcasts it from the phone alone (spending that output, plus phone coins if needed, to bring the fee up to today's rate), which resets the recovery delays well before the first year's single-key recovery opens after about 425 days. A monthly-only policy is therefore two HWW-signed transactions for two years. The renewal does not touch the first year's months, so unclaimed first-year months stay claimable with `phone authorize <step> --previous`. Deposits made after the ceremony are not covered by the renewal and need a new ceremony. `--years 1` keeps the yearly ceremony.

### Hard-locked savings

`anzen savings create --unlock 2030-01-01` creates a savings address that nothing can spend before 00:00 UTC on that date, not even both devices together. After the date phone and HWW spend it together; if one device is lost, the phone alone can recover it 425 days after the date and the HWW alone 455 days after. Every path is dated, so savings never need a ceremony or renewal and deposits can arrive at the same address forever. The first lock becomes the default deposit address (`anzen deposit-address`), which makes it the natural target for recurring income. Several locks with different dates can be held at once. Each lock records the keys it was created with, so a phone rotation (which cannot move locked coins) leaves its address unchanged.

`anzen coins` lists every vault and savings coin with how long it stays protected, most urgent first: vault coins count down to their phone-only recovery height (and flag a ceremony when it is within about 60 days), savings coins count down to their unlock date. Amounts and coin IDs stay hidden unless `--reveal` is passed.

Once the chain's median time passes the unlock date, `anzen phone savings-spend DEST --unlock YYYY-MM-DD --output spend.json` builds a spend of every coin in that lock at today's fee rate and adds the phone's signature; `anzen hww confirm-savings-spend spend.json --output approved.json` shows the destination, amount and fee before the HWW signs, and `anzen phone broadcast-savings-spend approved.json` sends it. `--unlock` can be left out when there is only one lock. If a device is lost, `anzen phone recover-savings DEST` works 425 days after the date and `anzen hww recover-savings DEST` 455 days after. After a phone-key rotation the phone finds the key that created the lock in its rotation history. Savings spends are built when they are used, not presigned, so they need no CPFP: the fee rate is fetched at that moment and capped at 1,000 sat/vB.

### Health checks and the recovery kit

`anzen health check` asks the phone and the HWW to sign a fresh, single-use challenge with their vault keys and verifies each signature against the vault policy. A pass proves the device still holds the right key; it never moves coins and costs nothing. Results are kept in `health.json`, and `anzen health status` shows when each device was last checked and when the next check is due (every six months). A rotated phone key starts over as unchecked.

`anzen recovery-kit --owner "Name" --output kit.html` writes a printable recovery kit for heirs and recovery friends: one self-contained HTML document, laid out as printed pages, that explains the two keys, the four situations someone can be in (both devices, HWW only, phone only, recovery friend), a timeline of when each path opens with real dates for every savings lock, numbered steps, a page to fill in by hand, and the exact descriptors for a technical helper. Print it or save it as PDF from any browser. The kit contains only public data and cannot move coins, but it reveals where the coins are, so keep it private and print a new one after a key rotation, a new savings lock, or a recovery-friend change.

### Naming an heir

An owner can name one heir, who holds a key of their own. The heir's key is added to every policy as one more leaf, so it must be named before `anzen init` (it is part of the vault address):

```text
vault:   tr(NUMS, { multi_a(2, phone, hww),
                    { { and_v(v:older(61200), pk(phone)), and_v(v:older(65535), pk(hww)) },
                      and_v(v:older(65535), pk(heir)) } })
savings: the savings policy above plus and_v(v:pk(heir), after(unlock + 485 days))
```

The heir's vault clock is the coin's age, like the recovery paths: 65,535 blocks (about 15 months, the longest relative timelock Bitcoin allows) after the coins last moved. While the owner is active, the yearly rollover keeps moving the vault coins, which restarts the heir's wait every time; when the owner stops, the coins stop moving and the heir's key opens. A health check cannot restart it, because only moving coins can. If the owner's phone is still running, its one presigned renewal can move the coins once more and push the date back by up to a year. On savings locks the heir's date is fixed: 485 days after the unlock date, a month after the HWW alone.

The heir never needs the owner's devices or secrets. On their own device they run `anzen heir init --name NAME` and give the owner the printed key, which the owner records with `anzen heir import --name NAME --key KEY` before `anzen init`. Later the heir rebuilds the vault from the descriptors printed in the recovery kit with `anzen heir restore --vault-descriptor D --savings-descriptor S`, checks dates with `anzen heir status`, and moves every coin their key can already open with `anzen heir claim ADDRESS`. The recovery kit gains a page that shows the heir's clock as a picture, a situation and step-by-step section for the heir, and the heir's dates on every timeline.

### Adding a YubiKey as a third key

An owner can add one YubiKey as an optional third key. With it, **any two of phone, hardware wallet and YubiKey** can move the coins at any time, so losing one device never means waiting. The YubiKey has no leaf of its own: it signs only together with one of the other two keys. Like the heir, it is part of the vault address, so it is added before `anzen init` (to add one to an existing vault, create a new vault with it and move the coins):

```text
vault:   tr(NUMS, { multi_a(2, phone/<0;1>, hww/<0;1>),
                    { { multi_a(2, phone/<4;5>, yubikey/<4;5>),
                        multi_a(2, hww/<6;7>,   yubikey/<6;7>) },
                      recovery leaves (and the heir, if named) } })
savings: the same pairs with after(unlock)
```

Each leaf gets its own derivation branch because a stock Ledger refuses a wallet policy that repeats a key expression. The cooperative leaf, the presigned yearly graph and the single-key recovery paths are unchanged.

The YubiKey is used only on a computer, never on the phone, so a stolen phone never holds two keys; `anzen yubikey init` refuses to run where the phone's or the hardware wallet's key lives. Its key is backed up as 24 words on paper. The prototype keeps it in a software key store on that computer, standing in for the key a real YubiKey will unlock.

```bash
# On the YubiKey's computer
anzen --data-dir yubikey yubikey init
# On the phone, before `anzen init`
anzen yubikey import --key "[fingerprint/86'/1'/100'/0/0]tpub..."
# Later, on the YubiKey's computer, from the descriptors in the recovery kit
anzen --data-dir yubikey yubikey restore --vault-descriptor "tr(...)"
```

To move the coins when a device is lost, the device you still have proposes and signs a sweep of every vault coin, and the YubiKey's computer checks it, signs it and broadcasts it:

```bash
# Hardware wallet lost: phone + YubiKey
anzen phone yubikey-sweep NEW_VAULT_ADDRESS --output sweep.json
# Phone lost: hardware wallet + YubiKey
anzen hww yubikey-sweep NEW_VAULT_ADDRESS --output sweep.json
# Either way, on the YubiKey's computer
anzen --data-dir yubikey yubikey confirm-sweep sweep.json
```

A YubiKey has no screen. The destination should be a new vault whose address was checked on a hardware wallet's screen, and the computer re-derives everything it signs from its own copy of the vault, so a forged proposal is refused. If a hardware wallet is lost but its 24 words are safe, the simplest fix is to restore them onto a new hardware wallet and carry on with phone and hardware wallet as before. With a YubiKey, the recovery kit becomes "three keys, any two", with a picture of the keys in hand for each case: lost phone, lost hardware wallet, lost YubiKey, one key left, and theft.

### Watching the vault

The delays only help if the owner hears about a move while there is still time to act. `anzen watch run` reads the chain from the owner's own Bitcoin Core node (every block since its last check, plus mempool spends through `gettxspendingprevout`) or Electrum server, and reports each transaction that touches the vault, an allowance month, the emergency controller or a savings lock:

| What happened | Level | What the owner is told |
| --- | --- | --- |
| Emergency withdrawal started | alert | Cancel it within the week with the HWW (`anzen hww revoke-policy`) |
| Coins moved with the phone alone, the HWW alone, or by an unknown script | alert | Move everything left with the other key now |
| The heir's key claimed coins | alert | Their long wait had passed |
| The phone claimed an allowance month | notice | If not you, pull the remaining months back with the HWW (`anzen hww revoke-policy <vault address>`) |
| The HWW moved allowance months | notice | That is the panic button; if not you, move the remaining coins with the phone |
| A cancel, a cooperative move not in the plan, or coins moved while the watcher was away | notice | Check that it was you |
| Rollover or renewal, a deposit, unused months returned to the vault | info | Nothing to do |

It also reminds the owner, at most weekly, when a vault coin's phone-alone path is two months from opening. Each transaction is reported once, from the mempool when the node sees it there. The watcher recognises the plan's own transactions by txid: at every policy activation the phone records the epoch's presigned rollover, renewal and emergency txids, plus the unlock date of every allowance month (from which each month's address follows), in `phone/watch-plan.json`. Any other spend is judged by the Taproot leaf its witness reveals.

`--notify-command` runs a shell command for every alert, with `ANZEN_ALERT_LEVEL`, `ANZEN_ALERT_TITLE` and `ANZEN_ALERT_MESSAGE` set and the text on stdin, so delivery can be email, Signal or a self-hosted push server. The alert text never contains amounts, addresses or txids, so it is safe to hand to a push service; `--reveal` adds them to the local output only. The watcher saves its progress only after every alert was delivered, so a failed delivery is raised again on the next check. Run it once from cron or a timer, or keep it running with `--every 60`; after three failed checks in a row it says it cannot see the chain.

The watcher holds no keys, so it can live on an always-on computer such as a home node. `anzen watch export --output plan.json` writes the public watch plan (descriptors and expected txids), and `anzen --data-dir watcher watch import plan.json` loads it there. Export again after each ceremony, new savings lock or key rotation. The plan cannot move coins but reveals the vault's balance and history, so keep it private.

Presigned transactions are convenience permissions, not custody. Losing them cannot lose the bitcoin because every vault output still has the three vault-script paths above, and every allowance month stays spendable by the HWW at any time and by the phone after its date.

For a concrete byte-level example of this graph—including txids, outpoints, locktimes, sequences, values, addresses, and scripts—see the checked-in [vault output test vector](test-vectors/vault-output-graph.json).

## Use the CLI manually

Start the regtest node and define an `anzen` shell helper:

```console
$ docker compose --profile manual up -d bitcoind
Network anzen_default Creating
Network anzen_default Created
Container anzen-bitcoind-1 Creating
Container anzen-bitcoind-1 Created
Container anzen-bitcoind-1 Starting
Container anzen-bitcoind-1 Started

$ anzen() { COMPOSE_PROGRESS=quiet docker compose run --rm cli "$@"; }
```

These examples use disposable regtest wallets. The simulated devices print their mnemonics for demonstration.

### Create a vault

Initialize each simulated device separately, then combine their public keys into the static cold-storage policy:

For mainnet, pass `--dangerously-enable-mainnet` to every command. Select a chain backend with `--chain-backend rpc|electrum`.

```console
$ anzen phone init
Simulated phone initialized (REGTEST ONLY)
Phone mnemonic: hospital suit remain guard kidney trial task hope arrow catch shoe ceiling pole tattoo space fatigue lens wrist narrow guess cruise rail riot concert
Phone vault key: b336b46856b0c7dd2e2a2d4ffde1d1e7788707cfd246ebb72bebd395a19fdaf0

$ anzen hww init
Simulated HWW initialized (REGTEST ONLY)
HWW mnemonic: switch announce harsh welcome cotton bike grace polar rug welcome scatter exercise lounge couch box parrot orchard ship execute dolphin defy fuel quick girl
HWW vault key: e905d6034668f206e34cbba40808f94dfc676f88a19930160239ee14aaef445f
HWW ready to wrap the descriptor-bound cloud backup at anzen init

$ anzen init
Vault initialized (REGTEST ONLY)
Cold storage descriptor: tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{multi_a(2,b336b46856b0c7dd2e2a2d4ffde1d1e7788707cfd246ebb72bebd395a19fdaf0,e905d6034668f206e34cbba40808f94dfc676f88a19930160239ee14aaef445f),{and_v(v:older(61200),pk(b336b46856b0c7dd2e2a2d4ffde1d1e7788707cfd246ebb72bebd395a19fdaf0)),and_v(v:older(65535),pk(e905d6034668f206e34cbba40808f94dfc676f88a19930160239ee14aaef445f))}})#ezseuq69
Vault address: bcrt1pk2xcl2m8p2kkwde8gq3tazx94ln8e9wxj49llakmz50zfg9md90qwug5ge
Phone recovery: 61,200 blocks (~14 months)
HWW recovery:   65,535 blocks (~15 months)
Monthly spending: disabled
Emergency access: disabled
Cloud recovery backup: phone key + descriptor encrypted; 0 recovery friends

$ anzen policy
Cold storage descriptor: tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{multi_a(2,b336b46856b0c7dd2e2a2d4ffde1d1e7788707cfd246ebb72bebd395a19fdaf0,e905d6034668f206e34cbba40808f94dfc676f88a19930160239ee14aaef445f),{and_v(v:older(61200),pk(b336b46856b0c7dd2e2a2d4ffde1d1e7788707cfd246ebb72bebd395a19fdaf0)),and_v(v:older(65535),pk(e905d6034668f206e34cbba40808f94dfc676f88a19930160239ee14aaef445f))}})#ezseuq69
Vault address: bcrt1pk2xcl2m8p2kkwde8gq3tazx94ln8e9wxj49llakmz50zfg9md90qwug5ge
Policy controller address: bcrt1pvn6qsn0t7u4q02vaf2wku8cnfrfns29qetz743fgvwhmuk3akers6ca203
Emergency connector reserve: 1000 sats
Phone recovery: 61,200 blocks (~14 months)
HWW recovery:   65,535 blocks (~15 months)
Monthly spending: disabled
Emergency access: disabled
```

The new vault starts with monthly spending and emergency access disabled. `anzen init` prints the static cold-storage descriptor, vault address, and recovery delays, but does not create or sign a spending policy.

### Use a Ledger as the HWW

A Ledger Nano S Plus, Nano X, Stax or Flex running the stock Bitcoin app (version 2.1 or later) can replace the simulated HWW. Use the "Bitcoin Test" app for regtest and signet. Build with USB support, and point `ANZEN_LEDGER` at the device:

```console
$ cargo build --release --features ledger-usb   # needs libudev-dev on Linux
$ export ANZEN_LEDGER=usb                        # or tcp:127.0.0.1:9999 for the Speculos emulator
$ anzen --signet hww init --ledger
```

The Ledger keeps its key. On first use of each policy the device asks you to register it ("Register account") and shows the vault address so you can compare it. Every later HWW step asks you to review a transaction or, to unlock the encrypted cloud backup, to sign the fixed message "Anzen: unlock the vault recovery backup (v1)". Ceremony transactions spend coins from outside the vault, so the Ledger warns about external inputs; that is expected.

### Use a BitBox02 as the HWW

A BitBox02 (the Bitcoin-only edition or the multi edition) with firmware 9.21 or later can replace the simulated HWW. Build with USB support, and point `ANZEN_BITBOX` at the device:

```console
$ cargo build --release --features bitbox-usb   # needs libudev-dev on Linux
$ export ANZEN_BITBOX=usb                        # or tcp:127.0.0.1:15423 for the BitBox02 simulator
$ anzen --signet hww init --bitbox
```

The BitBox02 keeps its key. The first time a computer talks to it, both show a pairing code; check that they match and confirm on the device. Setup reads the vault key at `m/86'/coin'/100'/0/0`, which the BitBox02 calls an unusual keypath: approve it once. On first use of each policy the device shows every key and spending path for you to register, then shows the vault address so you can compare it. New vaults use a "provably unspendable" internal key, which the BitBox02 recognizes and labels as such. Every later HWW step is a transaction review, or, to unlock the encrypted cloud backup, a confirmation of a key that is never used to hold coins.

The BitBox02 signs one policy per transaction, so two things differ from a Ledger:

- `anzen hww revoke-policy` pulls each month back in its own transaction, one review per month.
- Emergency access is not supported yet: its yearly transactions mix the vault with the emergency connector. Leave `--emergency-access-limit` at 0; the HWW refuses such a policy with a clear message rather than signing part of it.

The recovery kit asks for the hardware wallet's 24 secret words. If you set up the BitBox02 with a microSD backup, also write down its words (BitBoxApp: Device settings, Show recovery words). A Ledger's 24 words restored onto a BitBox02, or the reverse, give the same vault key.

### Set or replace the vault policy

The phone proposes the policy and signs its side of each vault input. The HWW independently rebuilds the rollover, every month's address and date, and the emergency transactions from its own copy of the vault, asks for one approval, and signs. Emergency connector inputs stay unsigned until the phone executes an action, so neither device commits revocation authority into the annual package. This real regtest policy combines a 0.1 BTC monthly limit with one cancellable 0.5 BTC emergency withdrawal and covers two years:

```console
$ anzen phone set-policy --monthly-limit 10000000 --emergency-access-limit 50000000 --years 2 --output policy.json
PHONE POLICY PROPOSAL
Vault address: bcrt1pdzgcemz7fghgj9j55zs5n7jlvd7yjy86k8cnqcxvyv4h6g9lqgcqkclxkn
Policy controller address: bcrt1pwnpgu9xwfzgqfuc6d472hx5y2rvqy3fru90utqwncwyh0jh32q7szxkwsn
Emergency connector reserve: 1000 sats
Monthly limit: 10000000 sats
Emergency access limit: 50000000 sats
Emergency access delay: 605184 seconds (~1 week)
Fee rate: 1 sat/vB
Total input: 200000000 sats
Allowance months: 12
  Month  1  unlocks 2026-11-19 22:25 UTC  10000000 sats  bcrt1pfhdexvyuu6rkkpnga8srp7kzm2pcy3dylrdshdxdygunf7t3jtvsjszgen
  Month  2  unlocks 2026-12-19 22:29 UTC  10000000 sats  bcrt1pay3pyepu39960hdgnq98apay4ru72rc5a60jc8tj9scw72k0y32srgue2k
  Month  3  unlocks 2027-01-18 22:33 UTC  10000000 sats  bcrt1pg7ya8vl24cr0swgvjd4vsernf77vfukqdrxe2hn2nwk3j3u3ktvsz86u66
  Month  4  unlocks 2027-02-17 22:38 UTC  10000000 sats  bcrt1pcthev7vfe4lruvwl80rd0rnjx7z86jc4qt4qy0wykn7r8qsec2jslnzadw
  Month  5  unlocks 2027-03-19 22:42 UTC  10000000 sats  bcrt1pjl6z7qywdwcgufwcajfua6lzvwypxp5zrp708eflugmhxvmw2hqq7carn7
  Month  6  unlocks 2027-04-18 22:46 UTC  10000000 sats  bcrt1pnjwch09q2x4k3mmtr5au5u0k3gjj82506c6smf0j66zpuvur90us0zh0wt
  Month  7  unlocks 2027-05-18 22:50 UTC  10000000 sats  bcrt1pht4yn3a9xmrggazeqj5hfjen2ccly2vpfpek2xsxv2run82z32vs3n3262
  Month  8  unlocks 2027-06-17 22:55 UTC  10000000 sats  bcrt1pa2wrdqr9snsq0vq8phf6knq3tqkk25mt9m73wjwhtjr7t3jye0us6kgy2h
  Month  9  unlocks 2027-07-17 22:59 UTC  10000000 sats  bcrt1ptlsj75w3vm4fz795xjlg5jlexncgha9eqs2rfepdd9d6mswnus6qyxfhps
  Month 10  unlocks 2027-08-16 23:03 UTC  10000000 sats  bcrt1pv26n5vgeqwc2q5ng948pu8q7h64f2atej5fvqrjk000jqwwadc9q6kk6ja
  Month 11  unlocks 2027-09-15 23:07 UTC  10000000 sats  bcrt1pye33d7dkzwzucv8rwzcx4hg4hl29v72u3dg6qupcs9q8junad44qwwhm0r
  Month 12  unlocks 2027-10-15 23:12 UTC  10000000 sats  bcrt1pc80eu4gv6tcc7g59hhsm4pmeg9c002ez2258lasrr032wxj4em0qes5jqr
Presigned renewal: second year included, broadcast after 31104000 seconds (~360 days)
Rollover txid: 1331ece49332eb7766372ecfdd56129a90f891fbe05224589b2858b83ae8c83c
Rollover fee: 721 sats
Allowance total: 120000000 sats
Back to the vault: 79998279 sats
Emergency trigger txid: f2e0fcf62967c3b6512f6aed3be5fa706a9ad3f9aefbcca233374c79cdba33f5
Emergency withdrawal txid: e79b8e85b3cc501969cfb2a501e5f585083aa0864520d917c4d6bdc3ec51d2d2
Emergency hot address: bcrt1p7jj8dxp637azcksvzte20ctzefas5rjtyhdavawpz4d5adxwfe7q0m2efl
Phone signed PSBTs: 3
Phone-signed policy proposal: policy.json

$ anzen hww confirm-policy policy.json --output approved-policy.json --yes
SIMULATED HWW — YEARLY POLICY APPROVAL
Policy controller address: bcrt1pwnpgu9xwfzgqfuc6d472hx5y2rvqy3fru90utqwncwyh0jh32q7szxkwsn
Emergency connector reserve: 1000 sats
Monthly limit: 10000000 sats
Emergency access limit: 50000000 sats
Emergency access delay: 605184 seconds (~1 week)
Allowance months: 12
Rollover txid: 1331ece49332eb7766372ecfdd56129a90f891fbe05224589b2858b83ae8c83c
Allowance total: 120000000 sats
Back to the vault: 79998279 sats
Emergency trigger txid: f2e0fcf62967c3b6512f6aed3be5fa706a9ad3f9aefbcca233374c79cdba33f5
Emergency withdrawal txid: e79b8e85b3cc501969cfb2a501e5f585083aa0864520d917c4d6bdc3ec51d2d2
Emergency hot address: bcrt1p7jj8dxp637azcksvzte20ctzefas5rjtyhdavawpz4d5adxwfe7q0m2efl
Phone signed PSBTs: 3
HWW validated and signed all 6 PSBTs after one approval
HWW-approved policy: approved-policy.json

$ anzen phone activate-policy approved-policy.json
Rollover broadcast: 1331ece49332eb7766372ecfdd56129a90f891fbe05224589b2858b83ae8c83c
Active monthly limit: 10000000 sats
Allowance months: 12
First month unlocks: 2026-11-19 22:25 UTC
Active emergency access: 50000000 sats
Encrypted emergency transaction set: trigger, withdrawal

$ anzen status
Network: regtest
Height: 103
Vault UTXOs: 1
Vault balance: 79998279 sats
Live policy controller outputs: 1
Allowance months waiting: 12 (0 unlocked, 120000000 sats)
```

`10000000` sats is 0.1 BTC and `50000000` sats is 0.5 BTC. Each year is three PSBTs: the rollover, the emergency trigger and the emergency withdrawal, so the HWW signs six for two years after one approval. Without emergency access each year is just its rollover. Nothing per month is presigned, and the policy contains no presigned revocations or cancellation. Set either limit to zero through the same three-step protocol to disable that feature. Policy JSON may also be piped with `--output -`; file handoff is clearer for the interactive HWW approval.

### Execute a monthly spend

Each month unlocks on its own date, and `anzen phone allowance` lists them. These outputs are from the monthly-spend test's own vault, right after its rollover confirmed:

```console
$ anzen phone allowance
Allowance months:
  Month  1  2026-11-19 22:24 UTC  10000000 sats  locked
  Month  2  2026-12-19 22:29 UTC  10000000 sats  locked
  Month  3  2027-01-18 22:33 UTC  10000000 sats  locked
  Month  4  2027-02-17 22:37 UTC  10000000 sats  locked
  Month  5  2027-03-19 22:42 UTC  10000000 sats  locked
  Month  6  2027-04-18 22:46 UTC  10000000 sats  locked
  Month  7  2027-05-18 22:50 UTC  10000000 sats  locked
  Month  8  2027-06-17 22:54 UTC  10000000 sats  locked
  Month  9  2027-07-17 22:59 UTC  10000000 sats  locked
  Month 10  2027-08-16 23:03 UTC  10000000 sats  locked
  Month 11  2027-09-15 23:07 UTC  10000000 sats  locked
  Month 12  2027-10-15 23:11 UTC  10000000 sats  locked
```

Before a month's date the phone is refused, because its leaf is locked by consensus. Afterwards `anzen phone authorize <step>` claims that month. `--limit` sends only part of it to the phone and the rest of the month back to the vault in the same transaction:

```console
$ anzen phone authorize 1
Error: month 1 unlocks after 2026-11-19 22:24 UTC

$ anzen phone authorize 1 --limit 1000000
Allowance month 1 claimed: b880158d59423004a73228cc0ba6c1e886021139a8aa859ad56cb55601b360b5
To this phone: 999819 sats
Back to the vault: 9000000 sats
Fee: 181 sats

$ anzen status
Network: regtest
Height: 115
Vault UTXOs: 2
Vault balance: 88999322 sats
Live policy controller outputs: 0
Allowance months waiting: 11 (0 unlocked, 110000000 sats)
```

A month can be claimed only once, and each later month keeps its own date even if earlier ones were claimed late:

```console
$ anzen phone authorize 1
Error: month 1 is not available: it was already claimed, returned or rescued

$ anzen phone authorize 2
Allowance month 2 claimed: 4969c481f7227380f3a6b0d128d445f61f8c4e42293a80715ebeedf97acfafd8
To this phone: 9999862 sats
Fee: 138 sats
```

The signed monthly limit is the security boundary. `--limit` is a phone-side choice and may be any value from zero through the signed monthly limit. After a presigned renewal, `--previous` claims a month from the previous year's ladder.

### Return or pull back unused months

`anzen phone return-unused` sends unclaimed months back to the vault without the HWW. By default a month goes back once the next month has unlocked, so unused allowance cannot pile up on the phone and a thief holding it gets at most about one month. `--all` also returns the current month. These outputs are from the monthly-return test:

```console
$ anzen phone return-unused
Returned 1 unused allowance month(s) to the vault: f8ff9a6fc8258ad6a3841206a56b50e1c9cebcf4473dff0656d2cbfd9813451d
Back to the vault: 9999862 sats
Fee: 138 sats

$ anzen phone return-unused --all
Returned 1 unused allowance month(s) to the vault: 56d7d79ca8b4d10804befebec508c663b559a3677278dd323c3ff592b78072d5
Back to the vault: 9999862 sats
Fee: 138 sats
```

The HWW is the panic button. `anzen hww revoke-policy` pulls every month back, locked or not, to the destination it shows (normally the vault address) and spends the emergency connector, which cancels emergency access. It works from the HWW's own record of the months it approved, so it needs neither the phone nor the phone's files. With a Ledger, each month is its own review:

```console
$ anzen hww revoke-policy bcrt1pdzgcemz7fghgj9j55zs5n7jlvd7yjy86k8cnqcxvyv4h6g9lqgcqkclxkn --yes
SIMULATED HWW — PULL ALLOWANCE BACK AND REVOKE EMERGENCY ACCESS
Allowance months to pull back: 12
  Month  1  2026-11-19 22:25 UTC  10000000 sats
  Month  2  2026-12-19 22:29 UTC  10000000 sats
  Month  3  2027-01-18 22:33 UTC  10000000 sats
  Month  4  2027-02-17 22:38 UTC  10000000 sats
  Month  5  2027-03-19 22:42 UTC  10000000 sats
  Month  6  2027-04-18 22:46 UTC  10000000 sats
  Month  7  2027-05-18 22:50 UTC  10000000 sats
  Month  8  2027-06-17 22:55 UTC  10000000 sats
  Month  9  2027-07-17 22:59 UTC  10000000 sats
  Month 10  2027-08-16 23:03 UTC  10000000 sats
  Month 11  2027-09-15 23:07 UTC  10000000 sats
  Month 12  2027-10-15 23:12 UTC  10000000 sats
Emergency access will be cancelled
Destination: bcrt1pdzgcemz7fghgj9j55zs5n7jlvd7yjy86k8cnqcxvyv4h6g9lqgcqkclxkn
HWW pulled back 12 allowance month(s): dba9b73e5ec517518375054e2fd4d7ebe7fbe4d7363dda49beae444027485d7a
Fee: 1047 sats
HWW policy revocation broadcast: 678aab01359ae556e55959a4fea360f3c8dcc6c5278c01592175ee8337c8d770
Revoked controller outputs: 1

$ anzen status
Network: regtest
Height: 104
Vault UTXOs: 3
Vault balance: 199998095 sats
Live policy controller outputs: 0
Allowance months waiting: 0 (0 unlocked, 0 sats)

$ anzen phone authorize 1
Error: month 1 is not available: it was already claimed, returned or rescued
```

### Use or cancel emergency access

The policy authorizes one emergency trigger per vault epoch. Starting it spends the rollover remainder into a staging output plus cold change and begins the Bitcoin-enforced cancellation window:

```console
$ anzen phone emergency initiate
Emergency access initiated: d13232941c779472ac175bc6587c7b674e975e2f859efe5a32b810ec4637dd30
Amount after delay: 50000000 sats
Cancellation window: 605184 seconds

$ anzen phone emergency withdraw
Error: failed to broadcast emergency access Withdrawal
```

After the trigger confirms and the one-week BIP68 delay elapses, the same command releases exactly the approved amount to the fresh hot-wallet address committed by the policy:

```console
$ anzen phone emergency withdraw
Emergency access withdrawal broadcast: df9a8ae1d948d7876f3a5db2e0fb1e5529a94f383ec291649f4302b1abeb94c3
```

Alternatively, the phone can cancel before maturity. These outputs are from the isolated cancellation test's own vault epoch:

```console
$ anzen phone emergency initiate
Emergency access initiated: 85fe845dfb9967b0468e32b012dcc4ea93329a952ee707fd9d1e1af67d9d58cd
Amount after delay: 50000000 sats
Cancellation window: 605184 seconds

$ anzen phone emergency cancel
Emergency access cancelled: 22e3f2066b72042c8975b26debca1f048aea3f0682ca3504ee0b0b756c7b1e55

$ anzen phone emergency withdraw
Error: failed to broadcast emergency access Withdrawal
```

Cancellation is constructed dynamically and spends only the withdrawal connector to fresh hot-wallet change. The staged 0.5 BTC remains in its existing vault output. Once cancellation confirms, the delayed withdrawal remains invalid even after its timelock expires because it committed to that exact connector outpoint. BIP68 uses 512-second units, so the enforced minimum is 605,184 seconds—seven days plus 6 minutes 24 seconds.

### Replace a lost phone

If the encrypted cloud backup survives, the HWW decrypts it into a portable recovery object. After installing that object on the replacement phone, pull the allowance months back to the vault and rotate immediately to a fresh phone key and vault address:

```console
$ anzen hww decrypt-phone-backup \
  .anzen-data/cloud/phone-seed-backup.json \
  --output phone-recovery.json
Decrypted phone recovery package: phone-recovery.json

$ anzen phone restore phone-recovery.json
Phone key restored from authenticated recovery package
Recovered phone mnemonic: silver method mango quarter donate gold craft current before bronze couple today nose bean custom jacket bridge endless sting tobacco supply glory famous jump

$ anzen phone rotate-key --output phone-rotation.json
Error: 12 allowance month(s) are still outside the vault. Return them first with the HWW: anzen hww revoke-policy bcrt1p3tq0qtw473kpmz36l3rrj7jz2p0flnfmg2ex275nq3lk0wtl882q4ay858

$ anzen hww revoke-policy bcrt1p3tq0qtw473kpmz36l3rrj7jz2p0flnfmg2ex275nq3lk0wtl882q4ay858 --yes
SIMULATED HWW — PULL ALLOWANCE BACK AND REVOKE EMERGENCY ACCESS
Allowance months to pull back: 12
  Month  1  2026-11-19 22:25 UTC  10000000 sats
  Month  2  2026-12-19 22:29 UTC  10000000 sats
  Month  3  2027-01-18 22:34 UTC  10000000 sats
  Month  4  2027-02-17 22:38 UTC  10000000 sats
  Month  5  2027-03-19 22:42 UTC  10000000 sats
  Month  6  2027-04-18 22:46 UTC  10000000 sats
  Month  7  2027-05-18 22:51 UTC  10000000 sats
  Month  8  2027-06-17 22:55 UTC  10000000 sats
  Month  9  2027-07-17 22:59 UTC  10000000 sats
  Month 10  2027-08-16 23:03 UTC  10000000 sats
  Month 11  2027-09-15 23:08 UTC  10000000 sats
  Month 12  2027-10-15 23:12 UTC  10000000 sats
Emergency access will be cancelled
Destination: bcrt1p3tq0qtw473kpmz36l3rrj7jz2p0flnfmg2ex275nq3lk0wtl882q4ay858
HWW pulled back 12 allowance month(s): 84b6acb0860f2143e7dff8113eaa02372a790abdf9159fa0824b394d1bc6b842
Fee: 1047 sats
HWW policy revocation broadcast: 26c2adb837e9cec9b70b6953a1f99c9372819f478d13ef7d3dae6177db47a231
Revoked controller outputs: 1

$ anzen phone rotate-key --output phone-rotation.json
PHONE-KEY ROTATION
New phone vault key: [51527c6f/86'/1'/100'/0/0]tpubDGBvhMY8r1hWf7rDyxAKjFf2pJZMmjsTbp9qpNZHxkapFSEdh2ur7FmrfxcHWL7W2JTwnX3NquZ4SEzP9Cv5j56EKkXu8i26HcduaSajoTB
New vault address: bcrt1prngf44htfjwn7v2vh9lwu2ct8qu434dp230d6euuzc2qupkqpldsu7scdn
Inputs: 3
Sent: 199997717 sats
Fee: 378 sats (1 sat/vB)
Monthly policy preserved: 10000000 sats
Renewed allowance months: 12
Renewed policy transactions: 3
Emergency access preserved: 50000000 sats
Phone-key rotation proposal: phone-rotation.json

$ anzen hww confirm-rotation phone-rotation.json \
  --output approved-phone-rotation.json --yes
PHONE-KEY ROTATION
New phone vault key: [51527c6f/86'/1'/100'/0/0]tpubDGBvhMY8r1hWf7rDyxAKjFf2pJZMmjsTbp9qpNZHxkapFSEdh2ur7FmrfxcHWL7W2JTwnX3NquZ4SEzP9Cv5j56EKkXu8i26HcduaSajoTB
New vault address: bcrt1prngf44htfjwn7v2vh9lwu2ct8qu434dp230d6euuzc2qupkqpldsu7scdn
Inputs: 3
Sent: 199997717 sats
Fee: 378 sats (1 sat/vB)
Monthly policy preserved: 10000000 sats
Renewed allowance months: 12
Renewed policy transactions: 3
Emergency access preserved: 50000000 sats
HWW validated and signed the phone-key rotation plus 3 renewed-policy PSBTs
HWW-approved phone-key rotation: approved-phone-rotation.json

$ anzen phone activate-rotation approved-phone-rotation.json
Emergency phone-key rotation broadcast: 6ff416a22ae09cf5c1a0704159229c2d2d132e7afaca52a8217317a587778b6e
Old hot-wallet funds swept to replacement phone: 26708fbcbb13886c969bc1d7a999ad485d0560d70d5c645f33e1da1773689d2b
Previous and replacement recovery keys retained in the rotation archive
Old vault address: bcrt1p3tq0qtw473kpmz36l3rrj7jz2p0flnfmg2ex275nq3lk0wtl882q4ay858
New vault address: bcrt1prngf44htfjwn7v2vh9lwu2ct8qu434dp230d6euuzc2qupkqpldsu7scdn
New phone mnemonic: echo spawn away file upper warfare thunder credit recall drum badge north duck pass table diesel extra frown scan label gasp cry fog little
Monthly policy preserved: 10000000 sats
Policy rollover broadcast: 160e44208189c2cf3d899404d16ef9e709dd03d64d73bf261e71857407a15791
Allowance months: 12
Emergency access preserved: 50000000 sats
```

Each allowance month's address is tied to the phone key that existed at the ceremony, so `phone rotate-key` refuses while any month is still outside the vault; `anzen hww revoke-policy <vault address>` brings them back and cancels emergency access first. The rotation preserves the HWW key, every configured recovery friend, and the active monthly and emergency-access limits. It spends any old controller that is still live to replacement-phone change, so no old-key policy authority survives. It then creates a new phone seed and descriptor-bound cloud envelope and sweeps the old vault cooperatively. The same proposal chains a fresh annual policy to that sweep, with a new ladder of months for the new phone key; one HWW prompt approves both, and all replacement artifacts and connectors use the new phone key. A disabled feature remains disabled after rotation.

### Configure social recovery

The backup payload contains the phone mnemonic and cold-storage descriptor, authenticated-encrypted under one random symmetric key. The HWW holds one encrypted copy of that key. Each recovery friend can hold another copy encrypted to their OpenPGP public key; the complete friend list is also authenticated by the symmetric key so cloud tampering cannot silently change who survives a later rotation. Friends are independent 1-of-N recipients, not threshold shares.

The key generator is a simulation convenience. In a real integration, import a public key whose private half stays under the friend's control:

```console
$ anzen social generate-friend-key --name "Alice <alice@example.test>" --public-key alice.pub.asc --private-key alice.sec.asc
Recovery friend OpenPGP key generated: 6e322d52f896b054dba2bb8dda013805966ab3b9
Public key: alice.pub.asc
Private key: alice.sec.asc (give only to the recovery friend)

$ anzen hww add-recovery-friend alice.pub.asc --yes
SIMULATED HWW — ADD RECOVERY FRIEND
OpenPGP fingerprint: 6e322d52f896b054dba2bb8dda013805966ab3b9
This friend gains the phone key and descriptor if they obtain the cloud backup
The 61,200-block phone recovery delay still applies to vault funds
Recovery friend added: 6e322d52f896b054dba2bb8dda013805966ab3b9
Cloud backup now grants this friend delayed phone recovery access
```

If both devices are lost, the friend can authenticate and decrypt the portable recovery package. The command displays the recovered public binding but writes the mnemonic only inside the private JSON output:

```console
$ anzen social decrypt-backup .anzen-data/cloud/phone-seed-backup.json --private-key alice.sec.asc --output friend-recovery.json
Social recovery decrypted and authenticated
Phone vault key: 45ef4f2557cc8efd84be6ce759be2c21ba1544414abd21e2faaa9adb89334461
Cold storage descriptor: tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{multi_a(2,45ef4f2557cc8efd84be6ce759be2c21ba1544414abd21e2faaa9adb89334461,63d061b6174bc25b0b8d59b67c2cfa5007047dd881d81d5e066aef41244aeb46),{and_v(v:older(61200),pk(45ef4f2557cc8efd84be6ce759be2c21ba1544414abd21e2faaa9adb89334461)),and_v(v:older(65535),pk(63d061b6174bc25b0b8d59b67c2cfa5007047dd881d81d5e066aef41244aeb46))}})#kl506xt5
Vault address: bcrt1p4cxhd740serrj3mj6uthpsrthagr5q2h2exmqzgzsamwpc280gzqs9x74x
Friend-decrypted phone recovery package: friend-recovery.json
```

Social recovery reconstructs `M`, not `H`, so it cannot bypass the vault script. After the real 61,200-block phone delay matures, the friend can sweep directly to replacement keys without installing either lost device:

```console
$ anzen social emergency-access .anzen-data/cloud/phone-seed-backup.json --private-key alice.sec.asc bcrt1p66y0chds0sua7yj22egwnm75hzzj4c5xpyqv4lqe4wtp8ffknpns3pmxl6
Social emergency-access sweep broadcast: bf4a1423cd2ce3e79647662ab638bcf6fa0285946916ad9787abc9bc0bc6a0b6
Inputs: 1
Sent: 199999854 sats
Fee: 146 sats (1 sat/vB)
On-chain phone recovery delay was enforced
```

Possession of a configured friend's private key is eventual phone-key capability. The HWW must therefore show that trust expansion clearly before adding a friend. The MVP-generated private key is unencrypted on disk; production friend-key UX and threshold recovery remain future work.

If the phone and its backup are permanently unavailable, initialize a replacement vault, wait the real 65,535-block HWW delay, and recover directly to its address:

```console
$ anzen --data-dir .replacement-vault phone init
Simulated phone initialized (REGTEST ONLY)
Phone mnemonic: inform skate door head purity crouch supreme veteran season depart trophy west jelly rain excess legend manage source brother immense drop enough choose behave
Phone vault key: 80156c4a68c7ffd16c68c10f1793e1fc0ca4c7c85453ddd8066f797f07a73a3a

$ anzen --data-dir .replacement-vault hww init
Simulated HWW initialized (REGTEST ONLY)
HWW mnemonic: awful elephant tray grant fitness purity lock slam sauce segment company brain off aware lawn reward mercy middle method fee cheap wrestle another erase
HWW vault key: b15a0cac758482440d0a8c869ab4cd902e3c85d44902cf3806a372f09779650c
HWW ready to wrap the descriptor-bound cloud backup at anzen init

$ anzen --data-dir .replacement-vault init
Vault initialized (REGTEST ONLY)
Cold storage descriptor: tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{multi_a(2,80156c4a68c7ffd16c68c10f1793e1fc0ca4c7c85453ddd8066f797f07a73a3a,b15a0cac758482440d0a8c869ab4cd902e3c85d44902cf3806a372f09779650c),{and_v(v:older(61200),pk(80156c4a68c7ffd16c68c10f1793e1fc0ca4c7c85453ddd8066f797f07a73a3a)),and_v(v:older(65535),pk(b15a0cac758482440d0a8c869ab4cd902e3c85d44902cf3806a372f09779650c))}})#ue605er0
Vault address: bcrt1p9nfuddc7xj2ruerl9u476pue3tw2nl5ceztt7zekn72ew444s8nqnnwkjt
Phone recovery: 61,200 blocks (~14 months)
HWW recovery:   65,535 blocks (~15 months)
Monthly spending: disabled
Emergency access: disabled
Cloud recovery backup: phone key + descriptor encrypted; 0 recovery friends

$ anzen --data-dir .replacement-vault policy
Cold storage descriptor: tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{multi_a(2,80156c4a68c7ffd16c68c10f1793e1fc0ca4c7c85453ddd8066f797f07a73a3a,b15a0cac758482440d0a8c869ab4cd902e3c85d44902cf3806a372f09779650c),{and_v(v:older(61200),pk(80156c4a68c7ffd16c68c10f1793e1fc0ca4c7c85453ddd8066f797f07a73a3a)),and_v(v:older(65535),pk(b15a0cac758482440d0a8c869ab4cd902e3c85d44902cf3806a372f09779650c))}})#ue605er0
Vault address: bcrt1p9nfuddc7xj2ruerl9u476pue3tw2nl5ceztt7zekn72ew444s8nqnnwkjt
Phone recovery: 61,200 blocks (~14 months)
HWW recovery:   65,535 blocks (~15 months)
Monthly spending: disabled
Emergency access: disabled

$ anzen hww recover bcrt1p9nfuddc7xj2ruerl9u476pue3tw2nl5ceztt7zekn72ew444s8nqnnwkjt
HWW recovery sweep broadcast: 157bdcb335fea687c1896042d5d4ee304b41933f1f140a1d55835b2ed82379d2
Inputs: 1
Sent: 4999999854 sats
Fee: 146 sats (1 sat/vB)
```

This delayed recovery moves the funds to a new phone key, a new HWW key, and a new static vault address.

### Replace a lost HWW

The phone can keep claiming allowance months as they unlock while the recovery delay runs. Initialize a replacement vault, wait the real 61,200-block phone delay, then sweep the old vault into its address:

```console
$ anzen --data-dir .replacement-vault phone init
Simulated phone initialized (REGTEST ONLY)
Phone mnemonic: inform skate door head purity crouch supreme veteran season depart trophy west jelly rain excess legend manage source brother immense drop enough choose behave
Phone vault key: 80156c4a68c7ffd16c68c10f1793e1fc0ca4c7c85453ddd8066f797f07a73a3a

$ anzen --data-dir .replacement-vault hww init
Simulated HWW initialized (REGTEST ONLY)
HWW mnemonic: awful elephant tray grant fitness purity lock slam sauce segment company brain off aware lawn reward mercy middle method fee cheap wrestle another erase
HWW vault key: b15a0cac758482440d0a8c869ab4cd902e3c85d44902cf3806a372f09779650c
HWW ready to wrap the descriptor-bound cloud backup at anzen init

$ anzen --data-dir .replacement-vault init
Vault initialized (REGTEST ONLY)
Cold storage descriptor: tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{multi_a(2,80156c4a68c7ffd16c68c10f1793e1fc0ca4c7c85453ddd8066f797f07a73a3a,b15a0cac758482440d0a8c869ab4cd902e3c85d44902cf3806a372f09779650c),{and_v(v:older(61200),pk(80156c4a68c7ffd16c68c10f1793e1fc0ca4c7c85453ddd8066f797f07a73a3a)),and_v(v:older(65535),pk(b15a0cac758482440d0a8c869ab4cd902e3c85d44902cf3806a372f09779650c))}})#ue605er0
Vault address: bcrt1p9nfuddc7xj2ruerl9u476pue3tw2nl5ceztt7zekn72ew444s8nqnnwkjt
Phone recovery: 61,200 blocks (~14 months)
HWW recovery:   65,535 blocks (~15 months)
Monthly spending: disabled
Emergency access: disabled
Cloud recovery backup: phone key + descriptor encrypted; 0 recovery friends

$ anzen --data-dir .replacement-vault policy
Cold storage descriptor: tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{multi_a(2,80156c4a68c7ffd16c68c10f1793e1fc0ca4c7c85453ddd8066f797f07a73a3a,b15a0cac758482440d0a8c869ab4cd902e3c85d44902cf3806a372f09779650c),{and_v(v:older(61200),pk(80156c4a68c7ffd16c68c10f1793e1fc0ca4c7c85453ddd8066f797f07a73a3a)),and_v(v:older(65535),pk(b15a0cac758482440d0a8c869ab4cd902e3c85d44902cf3806a372f09779650c))}})#ue605er0
Vault address: bcrt1p9nfuddc7xj2ruerl9u476pue3tw2nl5ceztt7zekn72ew444s8nqnnwkjt
Phone recovery: 61,200 blocks (~14 months)
HWW recovery:   65,535 blocks (~15 months)
Monthly spending: disabled
Emergency access: disabled

$ anzen phone recover bcrt1p9nfuddc7xj2ruerl9u476pue3tw2nl5ceztt7zekn72ew444s8nqnnwkjt
Phone recovery sweep broadcast: f9ee29feea85f607042a9338ea38e1eb4ae2854751d5b1f9c3823653fb58c340
Inputs: 1
Sent: 4999999854 sats
Fee: 146 sats (1 sat/vB)
```

The replacement vault has a fresh HWW key (and a fresh phone epoch), so the missing HWW can no longer participate. Approve a new monthly policy after the recovery confirms.

### Other cooperative sweeps

Arbitrary immediate vault sweeps retain the same explicit device boundary:

```console
$ anzen phone create-sweep bcrt1pdd5tyx8967m3xyqkjzdr0dd9dvmkpa9lauldk3cxmkvjgyulle2qnfk68w --output sweep.json
COOPERATIVE VAULT SWEEP
Destination: bcrt1pdd5tyx8967m3xyqkjzdr0dd9dvmkpa9lauldk3cxmkvjgyulle2qnfk68w
Inputs: 1
Sent: 198997378 sats
Fee: 162 sats (1 sat/vB)
Phone signed: true
Phone-signed cooperative sweep: sweep.json

$ anzen hww confirm-sweep sweep.json --output approved-sweep.json
COOPERATIVE VAULT SWEEP
Destination: bcrt1pdd5tyx8967m3xyqkjzdr0dd9dvmkpa9lauldk3cxmkvjgyulle2qnfk68w
Inputs: 1
Sent: 198997378 sats
Fee: 162 sats (1 sat/vB)
Phone signed: true
Type `approve` to confirm the cooperative sweep: approve
HWW validated and signed the cooperative sweep
HWW-approved cooperative sweep: approved-sweep.json

$ anzen phone broadcast-sweep approved-sweep.json
Cooperative vault sweep broadcast: 960a6390f3e655d6c3480d0903eb8244ca814af16d8de073b7178bfcaa2b0852
Inputs: 1
Sent: 198997378 sats
Fee: 162 sats (1 sat/vB)
```

## Run the end-to-end tests

Docker is the only host dependency:

```bash
./scripts/run-e2e.sh --list
./scripts/run-e2e.sh monthly-spend
./scripts/run-e2e.sh lost-phone lost-hww
./scripts/run-e2e.sh all
```

With no arguments, the runner behaves like `all`. Selected tests run serially, and each gets a fresh regtest chain and vault state so it can be read and reproduced independently. Separate runner invocations also use isolated Compose projects, so concurrent local tests cannot stop or erase one another. Output is limited to user actions, the corresponding CLI commands, essential policy/transaction results, expected safety rejections, and compact mining progress. Displayed commands omit the internal `--data-dir` argument, retain the terminal's default color, and show their results in muted grey. Every completed step starts a new paragraph with a short `✅` outcome so the test can be understood by skimming those lines.

The named tests cover setup/policy, dated monthly spend, returning unused months, the HWW pull-back, successful and cancelled one-week emergency access, partial funding, lost or stolen phone, lost or stolen HWW, missing cloud backup, both devices lost, OpenPGP social recovery, cloud compromise, both keys compromised, both on-time and forgotten annual rollover, and the presigned second-year renewal. The spend demonstrations fund exactly 2 BTC and create one rollover with twelve 0.1 BTC allowance months.

Recovery tests mine the real 61,200/65,535-block CSV delays, and the on-time rollover test mines a 52,560-block year before continuing to the old recovery deadline. Running one is intentionally slow; running `all` is substantially slower because every long-delay test proves its behavior on an independent chain.

## Run all tests

```bash
./scripts/run-tests.sh
```

This runs unit and CLI tests, focused real-node integration tests, and the slow recovery integration test. For fast local development without Docker:

```bash
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Project layout, development commands, and the hardware-firmware workflow are documented in [DEVELOPMENT.md](DEVELOPMENT.md). Implementation rationale and engineering trade-offs are recorded in [design-decisions.md](design-decisions.md).

## License

[MIT](LICENSE) © 2026 Luke Childs
