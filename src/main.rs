use anyhow::{Context, Result, bail};
use anzen::{cold_wallet, core, heir_wallet, hot_wallet, simple_wallet, yubikey_wallet};
use bitcoin::Network;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Parser)]
#[command(name = "anzen", version, about)]
struct Cli {
    /// Directory containing simulated device, cloud, and wallet state.
    #[arg(long, default_value = ".anzen-data", global = true)]
    data_dir: PathBuf,

    /// Required on initialization and every later command for a mainnet vault.
    #[arg(long, global = true)]
    dangerously_enable_mainnet: bool,

    /// Create the devices and vault on signet, the public test network. Later commands follow
    /// the vault's own network.
    #[arg(long, global = true, conflicts_with = "dangerously_enable_mainnet")]
    signet: bool,

    #[command(flatten)]
    chain: ChainArgs,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create the static cold-storage policy from initialized device keys.
    Init,
    /// Print the configured cold-storage and active programmable policy.
    Policy,
    /// Print vault and chain balances from the configured chain backend.
    Status,
    /// Actions performed by the simulated phone.
    Phone {
        #[command(subcommand)]
        command: PhoneCommand,
    },
    /// Actions performed by the simulated hardware wallet.
    Hww {
        #[command(subcommand)]
        command: HwwCommand,
    },
    /// OpenPGP social-recovery and delayed emergency-access actions.
    Social {
        #[command(subcommand)]
        command: SocialCommand,
    },
    /// Hard-locked savings addresses that nothing can spend before their date.
    Savings {
        #[command(subcommand)]
        command: SavingsCommand,
    },
    /// Print where recurring deposits should go (the default savings lock, if any).
    DepositAddress,
    /// Show how long each vault and savings coin stays protected, most urgent first.
    Coins {
        /// Show amounts and coin IDs instead of hiding them.
        #[arg(long)]
        reveal: bool,
    },
    /// Prove each device still holds its vault key, and show when the next check is due.
    Health {
        #[command(subcommand)]
        command: HealthCommand,
    },
    /// Name an heir before creating the vault, see when their key opens, and claim with it.
    Heir {
        #[command(subcommand)]
        command: HeirCommand,
    },
    /// The optional third key, used on a computer: any two of phone, hardware wallet and
    /// YubiKey can move the coins.
    Yubikey {
        #[command(subcommand)]
        command: YubikeyCommand,
    },
    /// Watch the vault from an always-on computer and send yourself an alert when coins move.
    Watch {
        #[command(subcommand)]
        command: WatchCommand,
    },
    /// Write a printable, plain-language recovery kit for heirs and recovery friends.
    RecoveryKit {
        /// Where to write the kit (an HTML file; print it or save it as PDF from any browser).
        #[arg(long)]
        output: PathBuf,
        /// The owner's name, shown on the cover.
        #[arg(long)]
        owner: Option<String>,
    },
    /// Simple mode: one phone, no hardware wallet. Savings open as dated payouts, one at a time.
    Simple {
        #[command(subcommand)]
        command: SimpleCommand,
    },
    /// Regtest-only node controls used by the end-to-end tests.
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
}

#[derive(Debug, Subcommand)]
enum HealthCommand {
    /// Ask a device (or both) to sign a fresh challenge and record the result.
    Check {
        /// Which device to check; both when omitted.
        #[arg(long, value_enum)]
        device: Option<HealthDevice>,
    },
    /// Show when each device was last checked and when the next check is due.
    Status,
}

#[derive(Debug, Subcommand)]
enum HeirCommand {
    /// Create a key for the heir with the simulated key store. Run before `anzen init`.
    Init {
        /// The heir's name, printed in the recovery kit.
        #[arg(long)]
        name: String,
    },
    /// Name an heir by the key their own wallet exported, as [fingerprint/path]xpub. Run before
    /// `anzen init`.
    Import {
        #[arg(long)]
        name: String,
        #[arg(long)]
        key: String,
    },
    /// On the heir's own device: rebuild the vault from the descriptors in the recovery kit.
    Restore {
        #[arg(long)]
        vault_descriptor: String,
        /// One per savings lock that names the heir.
        #[arg(long = "savings-descriptor")]
        savings_descriptors: Vec<String>,
    },
    /// Show who the heir is and when their key opens for the vault and each savings lock.
    Status,
    /// With the heir's key: move every vault and savings coin it can already open.
    Claim { destination: String },
}

#[derive(Debug, Subcommand)]
enum YubikeyCommand {
    /// On the YubiKey's computer: create its key with the simulated key store and show its 24
    /// backup words once. Refused where the phone's or hardware wallet's key lives.
    Init,
    /// On the phone: add the YubiKey to the new vault by its public key, as
    /// [fingerprint/path]xpub. Run before `anzen init`.
    Import {
        #[arg(long)]
        key: String,
    },
    /// On the YubiKey's computer: learn the vault from the descriptors in the recovery kit.
    Restore {
        #[arg(long)]
        vault_descriptor: String,
        #[arg(long = "savings-descriptor")]
        savings_descriptors: Vec<String>,
    },
    /// Show the YubiKey's key and the vault it belongs to.
    Status,
    /// Check a sweep the phone or hardware wallet proposed, sign it with the YubiKey and
    /// broadcast it.
    ConfirmSweep {
        proposal: PathBuf,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum WatchCommand {
    /// Check the chain for anything new: once (for cron or a timer), or every --every seconds.
    Run {
        /// Keep watching, checking this often (seconds, at least 10).
        #[arg(long, value_parser = clap::value_parser!(u64).range(10..))]
        every: Option<u64>,
        /// Shell command run for each alert. It gets ANZEN_ALERT_LEVEL, ANZEN_ALERT_TITLE and
        /// ANZEN_ALERT_MESSAGE, and the title and message on stdin. Alert text never contains
        /// amounts, addresses or txids, so it is safe to forward to a push service.
        #[arg(long, env = "ANZEN_NOTIFY_COMMAND")]
        notify_command: Option<String>,
        /// Also print amounts and txids in this computer's output.
        #[arg(long)]
        reveal: bool,
    },
    /// Write the watch plan (public descriptors and expected txids; no keys) for a watcher on
    /// another computer. Export again after each ceremony.
    Export {
        #[arg(long)]
        output: PathBuf,
    },
    /// On the watcher computer: load a watch plan exported from the phone.
    Import { plan: PathBuf },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum HealthDevice {
    Phone,
    Hww,
}

#[derive(Debug, Subcommand)]
enum SimpleCommand {
    /// Set up Simple mode from your 12 words (they can be the words your Fedi app shows).
    Init {
        /// The 12 words. Leave out to type them when asked.
        #[arg(long, env = "ANZEN_SIMPLE_WORDS", hide_env_values = true)]
        words: Option<String>,
        /// Also make a rescue paper: 12 more words to write down and keep somewhere else.
        #[arg(long)]
        rescue_paper: bool,
        /// How often a payout opens.
        #[arg(long, value_enum, default_value_t = simple_wallet::Frequency::Monthly)]
        every: simple_wallet::Frequency,
    },
    /// Show where to deposit and what is waiting there to be locked.
    Inbox,
    /// Lock everything in the inbox into dated payouts of this many sats each.
    Lock {
        #[arg(long)]
        amount: u64,
        /// Lock even when fees would take more than 2% of the savings a year.
        #[arg(long)]
        accept_high_fees: bool,
    },
    /// List payouts and when each opens.
    Payouts,
    /// Send every open payout to an address, for example your Fedi deposit address.
    Claim {
        #[arg(long)]
        to: String,
    },
    /// With the rescue paper, move every payout, open or not, to a safe address now.
    Rescue {
        #[arg(long)]
        to: String,
        /// The rescue paper's words. Leave out to type them when asked.
        #[arg(long, env = "ANZEN_RESCUE_WORDS", hide_env_values = true)]
        rescue_words: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum SavingsCommand {
    /// Create a savings address that unlocks at 00:00 UTC on the given date (YYYY-MM-DD).
    Create {
        #[arg(long)]
        unlock: String,
        /// Make it the default deposit address (the first lock always is).
        #[arg(long)]
        default: bool,
    },
    /// List savings locks and their addresses.
    List,
}

#[derive(Debug, Subcommand)]
enum PhoneCommand {
    /// Create the simulated phone key and hot-wallet account.
    Init {
        /// Grind a combined HWW/phone vault address beginning with bc1pvault or bcrt1pvault.
        #[arg(long)]
        vanity: bool,
    },
    /// Derive and persist the next hot-wallet receive address.
    ReceiveAddress,
    /// Send an exact amount from the phone hot wallet.
    Send { address: String, amount_sats: u64 },
    /// Propose a vault policy and add all phone signatures.
    SetPolicy {
        #[arg(long)]
        monthly_limit: u64,
        /// One delayed emergency withdrawal available during this vault epoch; zero disables it.
        #[arg(long, default_value_t = 0)]
        emergency_access_limit: u64,
        /// Years presigned in this ceremony. With 2, the second year's renewal is signed now and
        /// broadcast later with `phone renew`, so the HWW is needed only every two years.
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=2))]
        years: u8,
        #[arg(long)]
        output: PathBuf,
        /// Override the captured current Unix time (regtest-only).
        #[arg(long, hide = true)]
        now: Option<i64>,
    },
    /// Verify an HWW-approved policy, broadcast its rollover, and store artifacts.
    ActivatePolicy { approved_policy: PathBuf },
    /// Broadcast the presigned second-year renewal once it unlocks (360 days after the rollover).
    Renew,
    /// Show or choose how much to keep on the phone for bills and emergencies. Anything above it
    /// goes back to the vault before the next ceremony.
    Buffer {
        /// The amount to keep, in sats.
        #[arg(long)]
        set: Option<u64>,
    },
    /// Send everything above the buffer back to the vault. Run it just before a ceremony so the
    /// returned coins join the new months.
    ReturnLeftovers {
        /// Keep this many sats instead of the saved buffer.
        #[arg(long)]
        keep: Option<u64>,
    },
    /// List the allowance months: when each unlocks and whether it is still available.
    Allowance,
    /// Move one unlocked allowance month to this phone's wallet.
    Authorize {
        step: u8,
        /// Use the epoch a presigned renewal replaced, for its unclaimed months.
        #[arg(long)]
        previous: bool,
        /// Take only this many sats and send the rest of the month back to the vault.
        #[arg(long)]
        limit: Option<u64>,
    },
    /// Send unclaimed allowance months back to the vault. By default a month goes back once the
    /// next month has unlocked; `--all` also returns the current month.
    ReturnUnused {
        #[arg(long)]
        all: bool,
    },
    /// Execute or cancel the epoch's presigned emergency-access package.
    Emergency {
        #[command(subcommand)]
        command: EmergencyCommand,
    },
    /// Restore the phone key from an HWW-created recovery package.
    Restore { recovery: PathBuf },
    /// Sweep mature vault outputs using the phone-only recovery path.
    Recover { destination: String },
    /// Create and phone-sign a cooperative sweep proposal.
    CreateSweep {
        destination: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify and broadcast an HWW-approved cooperative sweep.
    BroadcastSweep { approved_sweep: PathBuf },
    /// Hardware wallet lost: propose moving every vault coin with the phone and the YubiKey.
    /// The YubiKey's computer finishes it with `anzen yubikey confirm-sweep`.
    YubikeySweep {
        destination: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Build and phone-sign a spend of every coin in an unlocked savings lock.
    SavingsSpend {
        destination: String,
        /// The lock's unlock date (YYYY-MM-DD); optional when there is only one lock.
        #[arg(long)]
        unlock: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify and broadcast an HWW-approved savings spend.
    BroadcastSavingsSpend { approved_spend: PathBuf },
    /// Move a savings lock's coins with the phone alone, 425 days after its unlock date.
    RecoverSavings {
        destination: String,
        #[arg(long)]
        unlock: Option<String>,
    },
    /// Propose a new phone key while preserving the active vault policy.
    RotateKey {
        /// Grind until the new vault address begins with bc1pvault or bcrt1pvault.
        #[arg(long)]
        vanity: bool,
        #[arg(long)]
        output: PathBuf,
    },
    /// Activate an HWW-approved key rotation and replacement monthly schedule.
    ActivateRotation { approved_rotation: PathBuf },
}

#[derive(Debug, Subcommand)]
enum EmergencyCommand {
    /// Start the one-week emergency-access cancellation window.
    Initiate,
    /// Withdraw the configured amount after the one-week delay.
    Withdraw,
    /// Cancel an initiated emergency withdrawal and return it to the vault.
    Cancel,
}

#[derive(Debug, Subcommand)]
enum HwwCommand {
    /// Create the simulated HWW key, or with --ledger or --bitbox use a hardware wallet's key.
    Init {
        /// Use a Ledger running the Bitcoin app (Bitcoin Test on signet and regtest) instead of
        /// the simulated HWW. Set ANZEN_LEDGER=tcp:HOST:PORT to use Ledger's emulator.
        #[arg(long, conflicts_with = "bitbox")]
        ledger: bool,
        /// Use a BitBox02 (firmware 9.21 or newer) instead of the simulated HWW. Set
        /// ANZEN_BITBOX=tcp:HOST:PORT to use the BitBox02 simulator.
        #[arg(long)]
        bitbox: bool,
    },
    /// Validate one high-level policy and sign its complete PSBT batch.
    ConfirmPolicy {
        proposal: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Approve non-interactively; intended for deterministic tests.
        #[arg(long)]
        yes: bool,
    },
    /// Decrypt a cloud phone backup into a portable recovery package.
    DecryptPhoneBackup {
        backup: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Add a friend's OpenPGP public key as a 1-of-N cloud recovery recipient.
    AddRecoveryFriend {
        public_key: PathBuf,
        /// Approve non-interactively; intended for deterministic tests.
        #[arg(long)]
        yes: bool,
    },
    /// Sweep mature vault outputs using the HWW-only recovery path.
    Recover { destination: String },
    /// Phone lost: propose moving every vault coin with the hardware wallet and the YubiKey.
    /// The YubiKey's computer finishes it with `anzen yubikey confirm-sweep`.
    YubikeySweep {
        destination: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Panic button: pull every allowance month back (locked or not) and cancel emergency access.
    RevokePolicy {
        /// Safe destination for the months, normally the vault address.
        destination: String,
        #[arg(long)]
        yes: bool,
    },
    /// Validate and sign a phone-created savings spend.
    ConfirmSavingsSpend {
        proposal: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        yes: bool,
    },
    /// Move a savings lock's coins with the HWW alone, 455 days after its unlock date.
    RecoverSavings {
        destination: String,
        #[arg(long)]
        unlock: Option<String>,
    },
    /// Validate and sign a phone-created cooperative sweep.
    ConfirmSweep {
        proposal: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        yes: bool,
    },
    /// Approve a phone-key rotation and any replacement policy in one prompt.
    ConfirmRotation {
        proposal: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SocialCommand {
    /// Generate a simulated recovery friend's OpenPGP keypair.
    GenerateFriendKey {
        #[arg(long)]
        name: String,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
    },
    /// Decrypt the phone key and descriptor using one configured friend's private key.
    DecryptBackup {
        backup: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Decrypt social recovery and sweep funds through the delayed phone-recovery path.
    EmergencyAccess {
        backup: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        destination: String,
    },
}

#[derive(Debug, Clone, Args)]
struct ChainArgs {
    /// Chain backend to use. Defaults to RPC on regtest and Electrum on mainnet.
    #[arg(long, env = "ANZEN_CHAIN_BACKEND", value_enum, global = true)]
    chain_backend: Option<ChainBackendKind>,
    #[arg(long, env = "ANZEN_RPC_URL", global = true)]
    rpc_url: Option<String>,
    #[arg(long, env = "ANZEN_RPC_USER", default_value = "anzen", global = true)]
    rpc_user: String,
    #[arg(
        long,
        env = "ANZEN_RPC_PASSWORD",
        default_value = "anzen",
        global = true
    )]
    rpc_password: String,
    /// Use one Electrum endpoint instead of the network's built-in defaults.
    #[arg(long, env = "ANZEN_ELECTRUM_URL", global = true)]
    electrum_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ChainBackendKind {
    Rpc,
    Electrum,
}

impl ChainArgs {
    fn selected_backend(&self, network: Network) -> Result<ChainBackendKind> {
        self.chain_backend.map_or_else(
            || match network {
                Network::Regtest => Ok(ChainBackendKind::Rpc),
                Network::Bitcoin | Network::Signet => Ok(ChainBackendKind::Electrum),
                other => bail!("unsupported vault network: {other}"),
            },
            Ok,
        )
    }

    fn connect_core(&self, network: Network) -> Result<core::chain::BitcoinCoreBackend> {
        let default_url = match network {
            Network::Regtest => "http://127.0.0.1:18443",
            Network::Bitcoin => "http://127.0.0.1:8332",
            Network::Signet => "http://127.0.0.1:38332",
            other => bail!("unsupported Bitcoin Core network: {other}"),
        };
        core::chain::BitcoinCoreBackend::connect(
            &core::chain::RpcConfig {
                url: self
                    .rpc_url
                    .clone()
                    .unwrap_or_else(|| default_url.to_owned()),
                user: self.rpc_user.clone(),
                password: self.rpc_password.clone(),
            },
            network,
        )
    }

    fn connect_electrum(&self, network: Network) -> Result<core::chain::ElectrumBackend> {
        match &self.electrum_url {
            Some(server) => core::chain::ElectrumBackend::connect(network, &[server.as_str()]),
            None => core::chain::ElectrumBackend::connect_default(network),
        }
    }

    fn connect_chain(&self, data_dir: &Path) -> Result<Box<dyn core::chain::Blockchain>> {
        let config = core::storage::load_config(data_dir)?;
        self.connect_chain_for(config.bitcoin_network()?)
    }

    fn connect_chain_for(&self, network: Network) -> Result<Box<dyn core::chain::Blockchain>> {
        match self.selected_backend(network)? {
            ChainBackendKind::Rpc => Ok(Box::new(self.connect_core(network)?)),
            ChainBackendKind::Electrum => Ok(Box::new(self.connect_electrum(network)?)),
        }
    }

    fn connect_hot(&self, data_dir: &Path) -> Result<Box<dyn hot_wallet::HotWalletBackend>> {
        let config = core::storage::load_config(data_dir)?;
        let network = config.bitcoin_network()?;
        match self.selected_backend(network)? {
            ChainBackendKind::Rpc => Ok(Box::new(self.connect_core(network)?)),
            ChainBackendKind::Electrum => Ok(Box::new(self.connect_electrum(network)?)),
        }
    }
}

#[derive(Debug, Subcommand)]
enum NodeCommand {
    /// Print the current regtest height and median-time-past.
    Info,
    /// Set the regtest node's mock Unix time.
    SetTime { timestamp: u64 },
    /// Mine blocks immediately to an explicit regtest address.
    Mine { blocks: u64, address: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let network = command_network(
        &cli.data_dir,
        cli.dangerously_enable_mainnet,
        cli.signet,
        &cli.command,
    )?;
    match cli.command {
        Command::Init => initialize_vault(&cli.data_dir, network),
        Command::Policy => print_active_policy(&cli.data_dir),
        Command::Status => print_status(&cli.data_dir, &cli.chain),
        Command::Savings { command } => run_savings(&cli.data_dir, command),
        Command::DepositAddress => print_deposit_address(&cli.data_dir),
        Command::Coins { reveal } => print_coins(&cli.data_dir, &cli.chain, reveal),
        Command::Phone { command } => run_phone(command, &cli.data_dir, &cli.chain, network),
        Command::Hww { command } => run_hww(command, &cli.data_dir, &cli.chain, network),
        Command::Social { command } => run_social(command, &cli.data_dir, &cli.chain),
        Command::Health { command } => run_health(&cli.data_dir, command),
        Command::Heir { command } => run_heir(command, &cli.data_dir, &cli.chain, network),
        Command::Yubikey { command } => run_yubikey(command, &cli.data_dir, &cli.chain, network),
        Command::Watch { command } => run_watch(command, &cli.data_dir, &cli.chain, network),
        Command::RecoveryKit { output, owner } => write_recovery_kit(&cli.data_dir, &output, owner),
        Command::Simple { command } => run_simple(command, &cli.data_dir, &cli.chain, network),
        Command::Node { command } => run_node(command, &cli.chain, network),
    }
}

fn initialize_vault(data_dir: &Path, network: Network) -> Result<()> {
    let config = core::storage::initialize_vault_for_network(data_dir, network)?;
    let backup = cold_wallet::create_cloud_recovery_backup(data_dir, &config)?;
    println!("Vault initialized ({})", network_label(network));
    if network == Network::Bitcoin {
        println!("DANGER: mainnet mode uses real bitcoin and fixed 1 sat/vB MVP fees");
    }
    println!("Cold storage descriptor: {}", config.vault_descriptor);
    println!("Vault address: {}", config.vault_address);
    println!(
        "Phone recovery: {} blocks (~14 months)",
        format_number(u64::from(config.phone_recovery_blocks))
    );
    println!(
        "HWW recovery:   {} blocks (~15 months)",
        format_number(u64::from(config.hww_recovery_blocks))
    );
    if let Some(heir) = &config.heir {
        println!(
            "Heir recovery:  {} blocks (~15 months) with {}'s own key",
            format_number(u64::from(core::HEIR_RECOVERY_BLOCKS)),
            heir.name
        );
    }
    println!("Monthly spending: disabled");
    println!("Emergency access: disabled");
    println!(
        "Cloud recovery backup: phone key + descriptor encrypted; {} recovery friends",
        backup.friends.len()
    );
    Ok(())
}

fn run_phone(
    command: PhoneCommand,
    data_dir: &Path,
    rpc_args: &ChainArgs,
    network: Network,
) -> Result<()> {
    match command {
        PhoneCommand::Init { vanity } => {
            if vanity {
                let target = hot_wallet::vanity_address_prefix(network)?;
                eprintln!(
                    "Grinding phone vault keys across all available CPU threads for {target}..."
                );
                let result = hot_wallet::initialize_vanity(data_dir, network, |attempts| {
                    eprintln!(
                        "Vanity search: {} candidates tested...",
                        format_number(attempts)
                    );
                })?;
                println!("Simulated phone initialized ({})", network_label(network));
                println!("Phone mnemonic: {}", result.device.mnemonic);
                println!("Phone vault key: {}", result.device.vault_pubkey);
                println!("Phone vault key index: {}", result.device.vault_key_index);
                println!("Vanity vault address: {}", result.vault_address);
                println!(
                    "Vanity search: {} candidates across {} threads",
                    format_number(result.attempts),
                    result.worker_count
                );
                return Ok(());
            }
            let phone = hot_wallet::initialize(data_dir, network)?;
            println!("Simulated phone initialized ({})", network_label(network));
            println!("Phone mnemonic: {}", phone.mnemonic);
            println!("Phone vault key: {}", phone.vault_pubkey);
        }
        PhoneCommand::ReceiveAddress => {
            let mut hot = hot_wallet::HotWallet::open_or_create(data_dir)?;
            let backend = rpc_args.connect_hot(data_dir)?;
            backend.sync_hot_wallet(&mut hot)?;
            println!("Hot receive address: {}", hot.next_receive_address()?);
        }
        PhoneCommand::Send {
            address,
            amount_sats,
        } => phone_send(data_dir, rpc_args, &address, amount_sats)?,
        PhoneCommand::SetPolicy {
            monthly_limit,
            emergency_access_limit,
            years,
            output,
            now,
        } => phone_set_policy(
            data_dir,
            rpc_args,
            monthly_limit,
            emergency_access_limit,
            years,
            now,
            &output,
        )?,
        PhoneCommand::ActivatePolicy { approved_policy } => {
            phone_activate_policy(data_dir, rpc_args, &approved_policy)?
        }
        PhoneCommand::Renew => {
            let backend = rpc_args.connect_hot(data_dir)?;
            let schedule = hot_wallet::activate_presigned_renewal(data_dir, backend.as_ref())?;
            println!("Presigned renewal broadcast: {}", schedule.rollover_txid);
            println!("Allowance months scheduled: {}", schedule.entries.len());
        }
        PhoneCommand::Buffer { set } => {
            if let Some(keep) = set {
                hot_wallet::set_buffer(data_dir, keep)?;
            }
            match hot_wallet::buffer(data_dir)? {
                Some(keep) => {
                    println!("Kept on the phone: {keep} sats");
                    let backend = rpc_args.connect_hot(data_dir)?;
                    if let Some((leftover, _)) = hot_wallet::leftovers(data_dir, backend.as_ref())?
                    {
                        println!("Above the buffer now: {leftover} sats");
                    }
                }
                None => println!(
                    "No buffer chosen yet: anzen phone buffer --set SATS (for example one month's spending)"
                ),
            }
        }
        PhoneCommand::ReturnLeftovers { keep } => {
            let backend = rpc_args.connect_hot(data_dir)?;
            match hot_wallet::return_leftovers(data_dir, backend.as_ref(), keep)? {
                Some(result) => {
                    println!("Leftovers returned to the vault: {}", result.txid);
                    println!("Returned: {} sats", result.returned_sats);
                    println!("Fee: {} sats (1 sat/vB)", result.fee_sats);
                    println!("Kept on the phone: {} sats", result.kept_sats);
                    println!(
                        "Once it confirms, run the ceremony (phone set-policy) so it joins the new months."
                    );
                }
                None => println!(
                    "Nothing to return: the phone holds no more than its buffer (amounts under {} sats stay).",
                    hot_wallet::MIN_LEFTOVER_RETURN_SATS
                ),
            }
        }
        PhoneCommand::Allowance => print_allowance(data_dir, rpc_args)?,
        PhoneCommand::Authorize {
            step,
            previous,
            limit,
        } => {
            let backend = rpc_args.connect_hot(data_dir)?;
            let result =
                hot_wallet::claim_month(data_dir, backend.as_ref(), step, previous, limit)?;
            println!("Allowance month {step} claimed: {}", result.txid);
            println!("To this phone: {} sats", result.sent_sats);
            if result.returned_sats > 0 {
                println!("Back to the vault: {} sats", result.returned_sats);
            }
            println!("Fee: {} sats", result.fee_sats);
        }
        PhoneCommand::ReturnUnused { all } => {
            let backend = rpc_args.connect_hot(data_dir)?;
            match hot_wallet::return_unclaimed_months(data_dir, backend.as_ref(), all)? {
                Some(result) => {
                    println!(
                        "Returned {} unused allowance month(s) to the vault: {}",
                        result.month_count, result.txid
                    );
                    println!("Back to the vault: {} sats", result.returned_sats);
                    println!("Fee: {} sats", result.fee_sats);
                }
                None => println!("No unused allowance months to return"),
            }
        }
        PhoneCommand::Emergency { command } => {
            let backend = rpc_args.connect_hot(data_dir)?;
            match command {
                EmergencyCommand::Initiate => {
                    let result = hot_wallet::initiate_emergency_access(data_dir, backend.as_ref())?;
                    println!("Emergency access initiated: {}", result.transaction_txid);
                    let schedule = hot_wallet::load_schedule(data_dir)?;
                    let emergency = schedule
                        .emergency_access
                        .context("active schedule omitted emergency access metadata")?;
                    println!("Amount after delay: {} sats", emergency.amount_sats);
                    println!("Cancellation window: {} seconds", emergency.delay_seconds);
                }
                EmergencyCommand::Withdraw => {
                    let txid = hot_wallet::withdraw_emergency_access(data_dir, backend.as_ref())?;
                    println!("Emergency access withdrawal broadcast: {txid}");
                }
                EmergencyCommand::Cancel => {
                    let txid = hot_wallet::cancel_emergency_access(data_dir, backend.as_ref())?;
                    println!("Emergency access cancelled: {txid}");
                }
            }
        }
        PhoneCommand::Restore { recovery } => {
            let package: core::recovery::PhoneRecoveryPackage = read_artifact(&recovery)?;
            let mnemonic = hot_wallet::restore_phone(data_dir, &package)?;
            println!("Phone key restored from authenticated recovery package");
            println!("Recovered phone mnemonic: {mnemonic}");
        }
        PhoneCommand::Recover { destination } => {
            let destination = configured_address(data_dir, &destination)?;
            let config = core::storage::load_config(data_dir)?;
            let backend = rpc_args.connect_chain(data_dir)?;
            let tip = backend.chain_tip()?;
            let utxos = backend.scan_vault(&config)?;
            let (transaction, result) =
                hot_wallet::recover(data_dir, &config, &utxos, tip.height, &destination)?;
            let txid = backend.broadcast(&transaction)?;
            if txid != result.txid {
                bail!("chain backend returned an unexpected phone recovery transaction ID");
            }
            print_sweep_result("Phone recovery sweep broadcast", &result);
        }
        PhoneCommand::CreateSweep {
            destination,
            output,
        } => phone_create_sweep(data_dir, rpc_args, &destination, &output)?,
        PhoneCommand::YubikeySweep {
            destination,
            output,
        } => {
            let destination = configured_address(data_dir, &destination)?;
            let config = core::storage::load_config(data_dir)?;
            let backend = rpc_args.connect_chain(data_dir)?;
            let utxos = backend.scan_vault(&config)?;
            let package =
                hot_wallet::create_yubikey_sweep(data_dir, &config, &utxos, &destination)?;
            report_pair_sweep(&package, artifact_reports_to_stderr(&output))?;
            write_artifact(&output, &package)?;
            report_artifact(&output, "Phone-signed sweep for the YubiKey")?;
        }
        PhoneCommand::BroadcastSweep { approved_sweep } => {
            let package: core::recovery::CooperativeSweepPackage = read_artifact(&approved_sweep)?;
            let backend = rpc_args.connect_hot(data_dir)?;
            let result =
                hot_wallet::broadcast_cooperative_sweep(data_dir, backend.as_ref(), &package)?;
            print_sweep_result("Cooperative vault sweep broadcast", &result);
        }
        PhoneCommand::SavingsSpend {
            destination,
            unlock,
            output,
        } => {
            let address = configured_address(data_dir, &destination)?;
            let unlock = unlock.as_deref().map(parse_unlock_date).transpose()?;
            let backend = rpc_args.connect_hot(data_dir)?;
            let package =
                hot_wallet::create_savings_spend(data_dir, backend.as_ref(), unlock, &address)?;
            report_savings_spend(&package, artifact_reports_to_stderr(&output))?;
            write_artifact(&output, &package)?;
            report_artifact(&output, "Phone-signed savings spend")?;
        }
        PhoneCommand::BroadcastSavingsSpend { approved_spend } => {
            let package: core::savings_spend::SavingsSpendPackage = read_artifact(&approved_spend)?;
            let backend = rpc_args.connect_hot(data_dir)?;
            let result = hot_wallet::broadcast_savings_spend(data_dir, backend.as_ref(), &package)?;
            print_spend_result("Savings spend broadcast", &result, package.fee_rate_sat_vb);
        }
        PhoneCommand::RecoverSavings {
            destination,
            unlock,
        } => {
            let address = configured_address(data_dir, &destination)?;
            let unlock = unlock.as_deref().map(parse_unlock_date).transpose()?;
            let backend = rpc_args.connect_hot(data_dir)?;
            let result = hot_wallet::recover_savings(data_dir, backend.as_ref(), unlock, &address)?;
            print_sweep_result_line("Phone savings recovery broadcast", &result);
        }
        PhoneCommand::RotateKey { vanity, output } => {
            let backend = rpc_args.connect_hot(data_dir)?;
            let package = if vanity {
                let target = hot_wallet::vanity_address_prefix(network)?;
                eprintln!(
                    "Preparing a vanity phone-key rotation for {target}; this may take a while..."
                );
                let result = hot_wallet::create_vanity_phone_rotation(
                    data_dir,
                    backend.as_ref(),
                    |attempts| {
                        eprintln!(
                            "Vanity search: {} candidates tested...",
                            format_number(attempts)
                        );
                    },
                )?;
                if result.resumed {
                    eprintln!(
                        "Reused the matching pending vanity key for {}",
                        result.package.new_vault_address
                    );
                } else {
                    eprintln!(
                        "Vanity search: {} candidates across {} threads",
                        format_number(result.attempts),
                        result.worker_count
                    );
                    eprintln!("Vanity vault address: {}", result.package.new_vault_address);
                }
                result.package
            } else {
                hot_wallet::create_phone_rotation(data_dir, backend.as_ref())?
            };
            report_rotation(&package, artifact_reports_to_stderr(&output))?;
            write_artifact(&output, &package)?;
            report_artifact(&output, "Phone-key rotation proposal")?;
        }
        PhoneCommand::ActivateRotation { approved_rotation } => {
            let package: core::recovery::PhoneRotationPackage = read_artifact(&approved_rotation)?;
            let backend = rpc_args.connect_hot(data_dir)?;
            let result = hot_wallet::activate_phone_rotation(data_dir, backend.as_ref(), &package)?;
            println!(
                "Emergency phone-key rotation broadcast: {}",
                result.sweep.txid
            );
            if let Some(txid) = result.controller_revocation_txid {
                println!("Old policy controllers revoked: {txid}");
            }
            if let Some(txid) = result.hot_wallet_sweep_txid {
                println!("Old hot-wallet funds swept to replacement phone: {txid}");
            }
            println!("Previous and replacement recovery keys retained in the rotation archive");
            println!("Old vault address: {}", result.old_address);
            println!("New vault address: {}", result.new_address);
            println!("New phone mnemonic: {}", result.new_phone_mnemonic);
            match result.renewed_schedule {
                Some(schedule) => {
                    println!(
                        "Monthly policy preserved: {} sats",
                        schedule.monthly_limit_sats
                    );
                    println!("Policy rollover broadcast: {}", schedule.rollover_txid);
                    println!("Allowance months: {}", schedule.entries.len());
                    if let Some(emergency) = &schedule.emergency_access {
                        println!("Emergency access preserved: {} sats", emergency.amount_sats);
                    }
                }
                None => println!("Programmable vault policy remains disabled"),
            }
        }
    }
    Ok(())
}

fn run_hww(
    command: HwwCommand,
    data_dir: &Path,
    rpc_args: &ChainArgs,
    network: Network,
) -> Result<()> {
    match command {
        HwwCommand::Init { ledger: true, .. } => {
            let key = cold_wallet::initialize_ledger(data_dir, network)?;
            println!("Ledger set up as the HWW ({})", network_label(network));
            println!("HWW vault key: {key}");
            println!("The Ledger keeps its key; nothing secret was written to disk");
        }
        HwwCommand::Init { bitbox: true, .. } => {
            let key = cold_wallet::initialize_bitbox(data_dir, network)?;
            println!("BitBox02 set up as the HWW ({})", network_label(network));
            println!("HWW vault key: {key}");
            println!("The BitBox02 keeps its key; nothing secret was written to disk");
        }
        HwwCommand::Init { .. } => {
            let hww = cold_wallet::initialize(data_dir, network)?;
            println!("Simulated HWW initialized ({})", network_label(network));
            println!("HWW mnemonic: {}", hww.mnemonic);
            println!("HWW vault key: {}", hww.vault_pubkey);
            println!("HWW ready to wrap the descriptor-bound cloud backup at anzen init");
        }
        HwwCommand::ConfirmPolicy {
            proposal,
            output,
            yes,
        } => hww_confirm_policy(data_dir, &proposal, &output, yes)?,
        HwwCommand::DecryptPhoneBackup { backup, output } => {
            let package = cold_wallet::decrypt_phone_backup_package(data_dir, &backup)?;
            write_artifact(&output, &package)?;
            report_artifact(&output, "Decrypted phone recovery package")?;
        }
        HwwCommand::AddRecoveryFriend { public_key, yes } => {
            let key = fs::read(&public_key).with_context(|| {
                format!("failed to read friend public key {}", public_key.display())
            })?;
            let proposed_fingerprint = core::social::friend_fingerprint(&key)?;
            hww_banner(data_dir, "ADD RECOVERY FRIEND");
            eprintln!("OpenPGP fingerprint: {proposed_fingerprint}");
            eprintln!(
                "This friend gains the phone key and descriptor if they obtain the cloud backup"
            );
            eprintln!("The 61,200-block phone recovery delay still applies to vault funds");
            require_hww_approval(yes, &public_key, "recovery friend")?;
            let fingerprint = cold_wallet::add_recovery_friend(data_dir, &key)?;
            println!("Recovery friend added: {fingerprint}");
            println!("Cloud backup now grants this friend delayed phone recovery access");
        }
        HwwCommand::Recover { destination } => {
            let destination = configured_address(data_dir, &destination)?;
            let config = core::storage::load_config(data_dir)?;
            let backend = rpc_args.connect_chain(data_dir)?;
            let tip = backend.chain_tip()?;
            let utxos = backend.scan_vault(&config)?;
            let (transaction, result) =
                cold_wallet::recover(data_dir, &config, &utxos, tip.height, &destination)?;
            let txid = backend.broadcast(&transaction)?;
            if txid != result.txid {
                bail!("chain backend returned an unexpected HWW recovery transaction ID");
            }
            print_sweep_result("HWW recovery sweep broadcast", &result);
        }
        HwwCommand::YubikeySweep {
            destination,
            output,
        } => {
            let destination = configured_address(data_dir, &destination)?;
            let config = core::storage::load_config(data_dir)?;
            let backend = rpc_args.connect_chain(data_dir)?;
            let utxos = backend.scan_vault(&config)?;
            let package =
                cold_wallet::create_yubikey_sweep(data_dir, &config, &utxos, &destination)?;
            report_pair_sweep(&package, artifact_reports_to_stderr(&output))?;
            write_artifact(&output, &package)?;
            report_artifact(&output, "HWW-signed sweep for the YubiKey")?;
        }
        HwwCommand::RevokePolicy { destination, yes } => {
            let destination = configured_address(data_dir, &destination)?;
            let config = core::storage::load_config(data_dir)?;
            let backend = rpc_args.connect_chain(data_dir)?;
            let connectors = backend.scan_connectors(&config)?;
            let months = hww_live_months(data_dir, &config, backend.as_ref())?;
            if connectors.is_empty() && months.is_empty() {
                bail!("no allowance months or emergency access are left to revoke");
            }
            hww_banner(data_dir, "PULL ALLOWANCE BACK AND REVOKE EMERGENCY ACCESS");
            eprintln!("Allowance months to pull back: {}", months.len());
            for rung in &months {
                eprintln!(
                    "  Month {:>2}  {}  {} sats",
                    rung.entry.step,
                    core::ladder::unlock_date(rung.entry.unlock),
                    rung.entry.value_sats
                );
            }
            if !connectors.is_empty() {
                eprintln!("Emergency access will be cancelled");
            }
            eprintln!("Destination: {destination}");
            if !months.is_empty() && cold_wallet::ledger::is_ledger_hww(data_dir) {
                eprintln!(
                    "Your Ledger reviews each month on its own: {} review(s).",
                    months.len()
                );
            }
            if !months.is_empty() && cold_wallet::bitbox::is_bitbox_hww(data_dir) {
                eprintln!(
                    "Your BitBox02 signs each month as its own transaction: {} review(s).",
                    months.len()
                );
            }
            require_hww_approval(yes, Path::new("controller-revocation"), "policy revocation")?;
            if !months.is_empty() {
                let fee_rate = backend
                    .estimate_fee_rate(core::fees::DEFAULT_CONFIRMATION_TARGET)?
                    .unwrap_or(core::DEFAULT_FEE_RATE_SAT_VB);
                let rescues =
                    cold_wallet::rescue_months(data_dir, &months, &destination, fee_rate)?;
                let months_per_transaction = months.len() / rescues.len();
                for (transaction, fee_sats) in rescues {
                    let expected_txid = transaction.compute_txid();
                    let txid = backend.broadcast(&transaction)?;
                    if txid != expected_txid {
                        bail!(
                            "chain backend returned an unexpected allowance rescue transaction ID"
                        );
                    }
                    println!("HWW pulled back {months_per_transaction} allowance month(s): {txid}");
                    println!("Fee: {fee_sats} sats");
                }
            }
            if !connectors.is_empty() {
                let transaction =
                    cold_wallet::revoke_policy(data_dir, &config, &connectors, &destination)?;
                let expected_txid = transaction.compute_txid();
                let txid = backend.broadcast(&transaction)?;
                if txid != expected_txid {
                    bail!("chain backend returned an unexpected policy revocation transaction ID");
                }
                println!("HWW policy revocation broadcast: {txid}");
                println!("Revoked controller outputs: {}", connectors.len());
            }
        }
        HwwCommand::ConfirmSavingsSpend {
            proposal,
            output,
            yes,
        } => {
            let package: core::savings_spend::SavingsSpendPackage = read_artifact(&proposal)?;
            core::savings_spend::validate_savings_spend(
                &core::storage::load_config(data_dir)?,
                &package,
            )?;
            report_savings_spend(&package, true)?;
            require_hww_approval(yes, proposal.as_path(), "savings spend")?;
            let approved = cold_wallet::approve_savings_spend(data_dir, &package)?;
            eprintln!("HWW validated and signed the savings spend");
            write_artifact(&output, &approved)?;
            report_artifact(&output, "HWW-approved savings spend")?;
        }
        HwwCommand::RecoverSavings {
            destination,
            unlock,
        } => {
            let destination = configured_address(data_dir, &destination)?;
            let unlock = unlock.as_deref().map(parse_unlock_date).transpose()?;
            let config = core::storage::load_config(data_dir)?;
            let lock = core::savings_spend::find_lock(&config, unlock)?.clone();
            let backend = rpc_args.connect_chain(data_dir)?;
            let tip = backend.chain_tip()?;
            let utxos = backend.scan_savings(&lock.address(config.bitcoin_network()?)?)?;
            let fee_rate = core::savings_spend::current_fee_rate(backend.as_ref())?;
            let (transaction, result) = cold_wallet::recover_savings(
                data_dir,
                &config,
                &lock,
                &utxos,
                tip.median_time,
                &destination,
                fee_rate,
            )?;
            let txid = backend.broadcast(&transaction)?;
            if txid != result.txid {
                bail!("chain backend returned an unexpected HWW savings recovery transaction ID");
            }
            print_sweep_result_line("HWW savings recovery broadcast", &result);
        }
        HwwCommand::ConfirmSweep {
            proposal,
            output,
            yes,
        } => {
            let package: core::recovery::CooperativeSweepPackage = read_artifact(&proposal)?;
            print_hww_sweep_prompt(&package, yes, proposal.as_path())?;
            let approved = cold_wallet::approve_cooperative_sweep(data_dir, &package)?;
            eprintln!("HWW validated and signed the cooperative sweep");
            write_artifact(&output, &approved)?;
            report_artifact(&output, "HWW-approved cooperative sweep")?;
        }
        HwwCommand::ConfirmRotation {
            proposal,
            output,
            yes,
        } => {
            let package: core::recovery::PhoneRotationPackage = read_artifact(&proposal)?;
            report_rotation(&package, true)?;
            require_hww_approval(yes, proposal.as_path(), "phone-key rotation")?;
            let approved = cold_wallet::approve_phone_rotation(data_dir, &package)?;
            if let Some(policy) = &approved.renewed_policy {
                eprintln!(
                    "HWW validated and signed the phone-key rotation plus {} renewed-policy PSBTs",
                    core::ceremony::manifest_transactions(&policy.manifest).len()
                );
            } else {
                eprintln!("HWW validated and signed the phone-key rotation");
            }
            write_artifact(&output, &approved)?;
            report_artifact(&output, "HWW-approved phone-key rotation")?;
        }
    }
    Ok(())
}

fn run_social(command: SocialCommand, data_dir: &Path, rpc_args: &ChainArgs) -> Result<()> {
    match command {
        SocialCommand::GenerateFriendKey {
            name,
            public_key,
            private_key,
        } => {
            if public_key == private_key {
                bail!("friend public and private key paths must be different");
            }
            let generated = core::social::generate_friend_key(&name)?;
            core::storage::write_private(&public_key, generated.public_key_armored.as_bytes())?;
            core::storage::write_private(&private_key, generated.private_key_armored.as_bytes())?;
            println!(
                "Recovery friend OpenPGP key generated: {}",
                generated.fingerprint
            );
            println!("Public key: {}", public_key.display());
            println!(
                "Private key: {} (give only to the recovery friend)",
                private_key.display()
            );
        }
        SocialCommand::DecryptBackup {
            backup,
            private_key,
            output,
        } => {
            let package = friend_recovery_package(data_dir, &backup, &private_key)?;
            println!("Social recovery decrypted and authenticated");
            println!("Phone vault key: {}", package.phone_vault_pubkey);
            println!("Cold storage descriptor: {}", package.vault_descriptor);
            println!("Vault address: {}", package.vault_address);
            write_artifact(&output, &package)?;
            report_artifact(&output, "Friend-decrypted phone recovery package")?;
        }
        SocialCommand::EmergencyAccess {
            backup,
            private_key,
            destination,
        } => {
            let package = friend_recovery_package(data_dir, &backup, &private_key)?;
            let config = core::storage::load_config(data_dir)?;
            let destination = configured_address(data_dir, &destination)?;
            let backend = rpc_args.connect_chain(data_dir)?;
            let tip = backend.chain_tip()?;
            let utxos = backend.scan_vault(&config)?;
            let plan = core::recovery::prepare_sweep(
                &config,
                &utxos,
                tip.height,
                core::recovery::SweepPath::PhoneRecovery,
                &destination,
            )?;
            let phone = core::keys::DeviceKeys::parse_for_network_at_index(
                &bitcoin::key::Secp256k1::new(),
                &package.phone_mnemonic,
                config.bitcoin_network()?,
                package.phone_vault_key_index,
            )?;
            let (transaction, result) = core::recovery::sign_recovery_sweep(
                plan,
                core::recovery::SweepPath::PhoneRecovery,
                &phone,
            )?;
            let txid = backend.broadcast(&transaction)?;
            if txid != result.txid {
                bail!("chain backend returned an unexpected emergency-access transaction ID");
            }
            print_sweep_result("Social emergency-access sweep broadcast", &result);
            println!("On-chain phone recovery delay was enforced");
        }
    }
    Ok(())
}

fn friend_recovery_package(
    data_dir: &Path,
    backup_path: &Path,
    private_key_path: &Path,
) -> Result<core::recovery::PhoneRecoveryPackage> {
    let config = core::storage::load_config(data_dir)?;
    let backup: core::social::CloudRecoveryBackup = core::storage::read_json(backup_path)?;
    let private_key = fs::read(private_key_path).with_context(|| {
        format!(
            "failed to read friend private key {}",
            private_key_path.display()
        )
    })?;
    let payload = core::social::decrypt_with_friend(&backup, &private_key)?;
    payload.validate_against(&config)?;
    Ok(core::recovery::PhoneRecoveryPackage {
        version: 2,
        kind: "phone-recovery".to_owned(),
        phone_mnemonic: payload.phone_mnemonic,
        phone_vault_key_index: payload.phone_vault_key_index,
        phone_vault_pubkey: payload.phone_vault_pubkey,
        vault_descriptor: payload.vault_descriptor,
        vault_address: payload.vault_address,
    })
}

fn phone_set_policy(
    data_dir: &Path,
    rpc_args: &ChainArgs,
    monthly_limit: u64,
    emergency_access_limit: u64,
    years: u8,
    now: Option<i64>,
    output: &Path,
) -> Result<()> {
    let backend = rpc_args.connect_hot(data_dir)?;
    if now.is_some() && backend.network() != Network::Regtest {
        bail!("--now is available only for deterministic regtest tests");
    }
    let timestamp = now.unwrap_or_else(|| chrono::Utc::now().timestamp());
    let now = chrono::DateTime::from_timestamp(timestamp, 0)
        .with_context(|| format!("invalid policy timestamp {timestamp}"))?;
    if let Ok(schedule) = hot_wallet::load_schedule(data_dir) {
        let config = core::storage::load_config(data_dir)?;
        let median_time = backend.chain_tip()?.median_time;
        let unlocked = hot_wallet::live_rungs_for(&config, backend.as_ref(), &schedule)?
            .iter()
            .filter(|rung| core::ladder::is_unlocked(&rung.entry, median_time))
            .count();
        if unlocked > 0 {
            eprintln!(
                "Note: {unlocked} unused allowance month(s) are outside the vault and not part of \
                 this ceremony. To include them, first run: anzen phone return-unused --all"
            );
        }
    }
    let leftover = hot_wallet::leftovers(data_dir, backend.as_ref())?.map_or(0, |(sats, _)| sats);
    if leftover >= hot_wallet::MIN_LEFTOVER_RETURN_SATS {
        eprintln!(
            "Note: the phone holds {leftover} sats above its buffer. To fold them into the new months, cancel, run `anzen phone return-leftovers`, wait for one confirmation, then start the ceremony again."
        );
    }
    let workspace = data_dir.join("phone/policy-proposal");
    reset_workspace(&workspace)?;
    let manifest = hot_wallet::propose_policy(
        data_dir,
        backend.as_ref(),
        now,
        monthly_limit,
        emergency_access_limit,
        years,
        &workspace,
    )?;
    let package = core::ceremony::package_from_batch(&workspace)?;
    print_manifest(&manifest, artifact_reports_to_stderr(output))?;
    write_artifact(output, &package)?;
    report_artifact(output, "Phone-signed policy proposal")?;
    Ok(())
}

fn hww_confirm_policy(data_dir: &Path, proposal: &Path, output: &Path, yes: bool) -> Result<()> {
    let package: core::ceremony::PolicyPackage = read_artifact(proposal)?;
    hww_banner(data_dir, "YEARLY POLICY APPROVAL");
    print_manifest(&package.manifest, true)?;
    if cold_wallet::ledger::is_ledger_hww(data_dir) {
        let reviews = core::ceremony::manifest_transactions(&package.manifest).len()
            + package.next.as_ref().map_or(0, |next| {
                core::ceremony::manifest_transactions(&next.manifest).len()
            });
        eprintln!(
            "Your Ledger will ask you to review {reviews} transaction(s). The first sends the \
             months above out of the vault; check that its amounts match this list."
        );
    }
    if cold_wallet::bitbox::is_bitbox_hww(data_dir) {
        if package.manifest.emergency_access_limit_sats > 0 {
            bail!(
                "emergency access is not available with a BitBox02 yet: its transactions spend the \
                 vault together with the emergency connector, and a BitBox02 signs only coins of \
                 one policy at a time. Ask the phone for a new proposal with \
                 --emergency-access-limit 0"
            );
        }
        let reviews = core::ceremony::manifest_transactions(&package.manifest).len()
            + package.next.as_ref().map_or(0, |next| {
                core::ceremony::manifest_transactions(&next.manifest).len()
            });
        eprintln!(
            "Your BitBox02 will ask you to review {reviews} transaction(s). The first sends the \
             months above out of the vault; check that its amounts match this list. The small \
             330-sat output of a presigned renewal goes to your phone's wallet, to raise its fee \
             later."
        );
    }
    require_hww_approval(yes, proposal, "complete vault policy")?;
    let workspace = data_dir.join("hww/policy-review");
    reset_workspace(&workspace)?;
    core::ceremony::materialize_policy_package(&package, &workspace)?;
    cold_wallet::approve_policy(data_dir, &workspace)?;
    let approved = core::ceremony::package_from_batch(&workspace)?;
    let signed = core::ceremony::manifest_transactions(&approved.manifest).len()
        + approved.next.as_ref().map_or(0, |next| {
            core::ceremony::manifest_transactions(&next.manifest).len()
        });
    eprintln!("HWW validated and signed all {signed} PSBTs after one approval");
    write_artifact(output, &approved)?;
    report_artifact(output, "HWW-approved policy")?;
    Ok(())
}

fn phone_activate_policy(data_dir: &Path, rpc_args: &ChainArgs, approved: &Path) -> Result<()> {
    let package = hot_wallet::open_approved_policy(data_dir, read_artifact(approved)?)?;
    if !package.manifest.phone_approved || !package.manifest.hww_approved {
        bail!("policy package requires both phone and HWW approval");
    }
    let workspace = data_dir.join("phone/policy-activation");
    reset_workspace(&workspace)?;
    core::ceremony::materialize_policy_package(&package, &workspace)?;
    let backend = rpc_args.connect_hot(data_dir)?;
    let schedule = hot_wallet::activate_policy(data_dir, backend.as_ref(), &workspace)?;
    println!("Rollover broadcast: {}", schedule.rollover_txid);
    println!("Active monthly limit: {} sats", schedule.monthly_limit_sats);
    println!("Allowance months: {}", schedule.entries.len());
    if let Some(first) = schedule.entries.first() {
        println!(
            "First month unlocks: {}",
            core::ladder::unlock_date(first.unlock)
        );
    }
    match &schedule.emergency_access {
        Some(emergency) => {
            println!("Active emergency access: {} sats", emergency.amount_sats);
            println!("Encrypted emergency transaction set: trigger, withdrawal");
        }
        None => println!("Emergency access: disabled"),
    }
    Ok(())
}

fn phone_create_sweep(
    data_dir: &Path,
    rpc_args: &ChainArgs,
    destination: &str,
    output: &Path,
) -> Result<()> {
    let address = configured_address(data_dir, destination)?;
    let backend = rpc_args.connect_hot(data_dir)?;
    let package = hot_wallet::create_cooperative_sweep(data_dir, backend.as_ref(), &address)?;
    report_sweep(&package, artifact_reports_to_stderr(output))?;
    write_artifact(output, &package)?;
    report_artifact(output, "Phone-signed cooperative sweep")?;
    Ok(())
}

fn print_hww_sweep_prompt(
    package: &core::recovery::CooperativeSweepPackage,
    yes: bool,
    proposal: &Path,
) -> Result<()> {
    report_sweep(package, true)?;
    require_hww_approval(yes, proposal, "cooperative sweep")
}

fn print_allowance(data_dir: &Path, rpc_args: &ChainArgs) -> Result<()> {
    let schedule = hot_wallet::load_schedule(data_dir)?;
    let backend = rpc_args.connect_hot(data_dir)?;
    let live = hot_wallet::live_rungs(data_dir, backend.as_ref())?;
    let median_time = backend.chain_tip()?.median_time;
    let print_epoch = |title: &str, entries: &[core::ceremony::ScheduleEntry], flag: &str| {
        if entries.is_empty() {
            return;
        }
        println!("{title}");
        for entry in entries {
            let state = if !live.iter().any(|rung| rung.outpoint() == entry.outpoint) {
                "used".to_owned()
            } else if core::ladder::is_unlocked(entry, median_time) {
                format!("available: anzen phone authorize {}{flag}", entry.step)
            } else {
                "locked".to_owned()
            };
            println!(
                "  Month {:>2}  {}  {} sats  {state}",
                entry.step,
                core::ladder::unlock_date(entry.unlock),
                entry.value_sats
            );
        }
    };
    print_epoch(
        "Previous year's months:",
        &schedule.previous_entries,
        " --previous",
    );
    print_epoch("Allowance months:", &schedule.entries, "");
    Ok(())
}

fn phone_send(
    data_dir: &Path,
    rpc_args: &ChainArgs,
    address: &str,
    amount_sats: u64,
) -> Result<()> {
    let address = configured_address(data_dir, address)?;
    let backend = rpc_args.connect_hot(data_dir)?;
    let mut hot = hot_wallet::HotWallet::open_or_create(data_dir)?;
    backend.sync_hot_wallet(&mut hot)?;
    let (transaction, fee_sats) = hot.build_payment(address.script_pubkey(), amount_sats)?;
    let txid = backend.broadcast(&transaction)?;
    println!("Hot-wallet payment broadcast: {txid}");
    println!("Destination: {address}");
    println!("Amount: {amount_sats} sats");
    println!("Fee: {fee_sats} sats (1 sat/vB)");
    Ok(())
}

fn print_active_policy(data_dir: &Path) -> Result<()> {
    let config = core::storage::load_config(data_dir)?;
    let controller = core::policy::ControllerPolicy::new_for_network(
        config.phone_vault_pubkey.parse()?,
        config.hww_vault_pubkey.parse()?,
        config.internal_key,
        config.bitcoin_network()?,
    )?;
    println!("Cold storage descriptor: {}", config.vault_descriptor);
    println!("Vault address: {}", config.vault_address);
    println!("Policy controller address: {}", controller.address);
    println!(
        "Emergency connector reserve: {} sats",
        core::CONNECTOR_VALUE_SATS
    );
    println!(
        "Phone recovery: {} blocks (~14 months)",
        format_number(u64::from(config.phone_recovery_blocks))
    );
    println!(
        "HWW recovery:   {} blocks (~15 months)",
        format_number(u64::from(config.hww_recovery_blocks))
    );
    if config.monthly_limit_sats == 0 {
        println!("Monthly spending: disabled");
    } else {
        println!("Monthly limit: {} sats", config.monthly_limit_sats);
        if let Ok(schedule) = hot_wallet::load_schedule(data_dir) {
            println!("Allowance months: {}", schedule.entries.len());
            if let (Some(first), Some(last)) = (schedule.entries.first(), schedule.entries.last()) {
                println!(
                    "First month unlocks: {}",
                    core::ladder::unlock_date(first.unlock)
                );
                println!(
                    "Last month unlocks:  {}",
                    core::ladder::unlock_date(last.unlock)
                );
            }
        }
    }
    if config.emergency_access_limit_sats == 0 {
        println!("Emergency access: disabled");
    } else {
        println!(
            "Emergency access limit: {} sats",
            config.emergency_access_limit_sats
        );
        println!(
            "Emergency access delay: {} seconds (~1 week)",
            core::EMERGENCY_ACCESS_DELAY_SECONDS
        );
    }
    Ok(())
}

fn run_yubikey(
    command: YubikeyCommand,
    data_dir: &Path,
    rpc_args: &ChainArgs,
    network: Network,
) -> Result<()> {
    match command {
        YubikeyCommand::Init => {
            let yubikey = yubikey_wallet::initialize(data_dir, network)?;
            println!("YubiKey key: {}", yubikey.vault_pubkey);
            if let Some(words) = yubikey.mnemonic {
                println!(
                    "YubiKey backup words (write them on paper, keep them apart from the hardware wallet's): {words}"
                );
            }
            println!(
                "Next, on the phone before `anzen init`: anzen yubikey import --key {}",
                yubikey.vault_pubkey
            );
        }
        YubikeyCommand::Import { key } => {
            let yubikey = yubikey_wallet::import(data_dir, network, &key)?;
            println!("YubiKey key: {}", yubikey.vault_pubkey);
            println!(
                "The vault created by `anzen init` will open with any two of phone, hardware wallet and YubiKey."
            );
        }
        YubikeyCommand::Restore {
            vault_descriptor,
            savings_descriptors,
        } => {
            let config = yubikey_wallet::restore(
                data_dir,
                network,
                &vault_descriptor,
                &savings_descriptors,
            )?;
            println!(
                "Vault learned from the recovery kit: {}",
                config.vault_address
            );
            println!(
                "This computer can now confirm a sweep the phone or the hardware wallet proposes."
            );
        }
        YubikeyCommand::Status => {
            match core::storage::load_yubikey(data_dir, network)? {
                Some(key) => println!("YubiKey key: {key}"),
                None => println!("No YubiKey is set up here."),
            }
            if core::storage::config_exists(data_dir) {
                let config = core::storage::load_config(data_dir)?;
                match config.yubikey_key()? {
                    Some(_) => {
                        println!("Vault: {}", config.vault_address);
                        println!(
                            "Any two of phone, hardware wallet and YubiKey can move the coins."
                        );
                    }
                    None => println!(
                        "This vault has no YubiKey. To add one, set up a new vault with it and move the coins there."
                    ),
                }
            }
        }
        YubikeyCommand::ConfirmSweep { proposal, yes } => {
            let package: core::recovery::PairSweepPackage = read_artifact(&proposal)?;
            let config = core::storage::load_config(data_dir)?;
            // Check everything before asking the person to approve.
            core::recovery::validate_pair_sweep(&config, &package)?;
            report_pair_sweep(&package, true)?;
            require_approval(yes, proposal.as_path(), "sweep with the YubiKey", "YubiKey")?;
            let (transaction, result) = yubikey_wallet::confirm_sweep(data_dir, &config, &package)?;
            let backend = rpc_args.connect_chain(data_dir)?;
            let txid = backend.broadcast(&transaction)?;
            if txid != result.txid {
                bail!("chain backend returned an unexpected sweep transaction ID");
            }
            print_sweep_result("YubiKey sweep broadcast", &result);
        }
    }
    Ok(())
}

fn run_heir(
    command: HeirCommand,
    data_dir: &Path,
    rpc_args: &ChainArgs,
    network: Network,
) -> Result<()> {
    match command {
        HeirCommand::Init { name } => {
            let heir = heir_wallet::initialize(data_dir, network, &name)?;
            println!("Heir named: {}", heir.name);
            println!("Heir key: {}", heir.vault_pubkey);
            if let Some(words) = heir.mnemonic {
                println!(
                    "Heir's secret words (give these to {} only): {words}",
                    heir.name
                );
            }
            println!("Their key will be in the vault created by `anzen init`.");
        }
        HeirCommand::Import { name, key } => {
            let heir = heir_wallet::import(data_dir, network, &name, &key)?;
            println!("Heir named: {}", heir.name);
            println!("Heir key: {}", heir.vault_pubkey);
            println!("Their key will be in the vault created by `anzen init`.");
        }
        HeirCommand::Restore {
            vault_descriptor,
            savings_descriptors,
        } => {
            let config =
                heir_wallet::restore(data_dir, network, &vault_descriptor, &savings_descriptors)?;
            println!(
                "Vault rebuilt from the recovery kit: {}",
                config.vault_address
            );
            println!("Savings locks: {}", config.savings_locks.len());
            println!("Next: anzen heir status, then anzen heir claim <address> when it opens");
        }
        HeirCommand::Status => {
            let config = core::storage::load_config(data_dir)?;
            let Some(heir) = &config.heir else {
                println!("No heir is named for this vault.");
                println!(
                    "An heir is named before the vault is created: anzen heir init --name NAME"
                );
                return Ok(());
            };
            println!("Heir: {}", heir.name);
            println!("Heir key: {}", heir.vault_pubkey);
            let backend = rpc_args.connect_chain(data_dir)?;
            let tip = backend.chain_tip()?;
            let utxos = backend.scan_vault(&config)?;
            match utxos.first() {
                Some(oldest) => print_recovery_activation(
                    "Heir (vault coins that stop moving)",
                    oldest.confirmation_height + u64::from(core::HEIR_RECOVERY_BLOCKS),
                    tip.height + 1,
                    tip.median_time,
                ),
                None => println!("Vault: no coins"),
            }
            println!(
                "Every time the owner's vault coins move, the heir's wait starts again from that day."
            );
            for lock in &config.savings_locks {
                let opens = match &lock.heir_vault_pubkey {
                    Some(key) if *key == heir.vault_pubkey => format_unix_date(
                        lock.policy(config.bitcoin_network()?)?
                            .earliest_lock_time(core::policy::SpendPath::Heir),
                    ),
                    _ => "never (created without this heir)".to_owned(),
                };
                println!(
                    "Savings until {}: heir's key opens {opens}",
                    format_unix_date(lock.unlock)
                );
            }
        }
        HeirCommand::Claim { destination } => {
            let destination = configured_address(data_dir, &destination)?;
            let config = core::storage::load_config(data_dir)?;
            let network = config.bitcoin_network()?;
            let backend = rpc_args.connect_chain(data_dir)?;
            let tip = backend.chain_tip()?;
            let mut claimed = 0;
            let utxos = backend.scan_vault(&config)?;
            if utxos.is_empty() {
                println!("Vault: no coins");
            } else {
                match heir_wallet::claim_vault(data_dir, &config, &utxos, tip.height, &destination)
                {
                    Ok((transaction, result)) => {
                        let txid = backend.broadcast(&transaction)?;
                        if txid != result.txid {
                            bail!("chain backend returned an unexpected heir claim transaction ID");
                        }
                        print_sweep_result_line("Heir vault claim broadcast", &result);
                        claimed += 1;
                    }
                    Err(error) => println!("Vault: not yet. {error:#}"),
                }
            }
            for lock in &config.savings_locks {
                let label = format!("Savings until {}", format_unix_date(lock.unlock));
                if lock.heir_vault_pubkey.is_none() {
                    println!("{label}: created without an heir");
                    continue;
                }
                let utxos = backend.scan_savings(&lock.address(network)?)?;
                if utxos.is_empty() {
                    println!("{label}: no coins");
                    continue;
                }
                let fee_rate = core::savings_spend::current_fee_rate(backend.as_ref())?;
                match heir_wallet::claim_savings(
                    data_dir,
                    &config,
                    lock,
                    &utxos,
                    tip.median_time,
                    &destination,
                    fee_rate,
                ) {
                    Ok((transaction, result)) => {
                        let txid = backend.broadcast(&transaction)?;
                        if txid != result.txid {
                            bail!("chain backend returned an unexpected heir claim transaction ID");
                        }
                        print_sweep_result_line(
                            &format!("Heir claim of {label} broadcast"),
                            &result,
                        );
                        claimed += 1;
                    }
                    Err(error) => println!("{label}: not yet. {error:#}"),
                }
            }
            if claimed == 0 {
                bail!("the heir's key cannot move any coins yet");
            }
        }
    }
    Ok(())
}

fn run_health(data_dir: &Path, command: HealthCommand) -> Result<()> {
    use core::health::{self, Device};
    let config = core::storage::load_config(data_dir)?;
    match command {
        HealthCommand::Check { device } => {
            let devices = match device {
                Some(HealthDevice::Phone) => vec![Device::Phone],
                Some(HealthDevice::Hww) => vec![Device::Hww],
                None => Device::ALL.to_vec(),
            };
            let mut failed = false;
            for device in devices {
                let challenge =
                    health::Challenge::new(&config, device, chrono::Utc::now().timestamp())?;
                let answer = match device {
                    Device::Phone => hot_wallet::sign_health_challenge(data_dir, &challenge),
                    Device::Hww => cold_wallet::sign_health_challenge(data_dir, &challenge),
                };
                match answer.and_then(|signature| health::verify(&challenge, &signature)) {
                    Ok(record) => {
                        health::append_record(data_dir, record)?;
                        println!(
                            "{}: healthy. It still holds the vault key. Next check due {}.",
                            device.label(),
                            format_unix_date_i64(
                                challenge.issued_at + health::HEALTH_CHECK_INTERVAL_SECS
                            )
                        );
                    }
                    Err(error) => {
                        failed = true;
                        println!("{}: FAILED. {error:#}", device.label());
                    }
                }
            }
            if failed {
                bail!(
                    "a device failed its health check; replace it while the other key still works"
                );
            }
        }
        HealthCommand::Status => {
            let history = health::load_history(data_dir)?;
            let now = chrono::Utc::now().timestamp();
            for device in Device::ALL {
                let line = match health::device_health(&config, &history, device, now) {
                    health::DeviceHealth::NeverChecked => {
                        "never checked. Run: anzen health check".to_owned()
                    }
                    health::DeviceHealth::Healthy { checked_at, due_at } => format!(
                        "healthy, checked {}. Next check due {}.",
                        format_unix_date_i64(checked_at),
                        format_unix_date_i64(due_at)
                    ),
                    health::DeviceHealth::Due { checked_at, .. } => format!(
                        "check overdue, last checked {}. Run: anzen health check",
                        format_unix_date_i64(checked_at)
                    ),
                };
                println!("{}: {line}", device.label());
            }
        }
    }
    Ok(())
}

fn write_recovery_kit(data_dir: &Path, output: &Path, owner: Option<String>) -> Result<()> {
    use core::{health, kit};
    let config = core::storage::load_config(data_dir)?;
    let network = config.bitcoin_network()?;
    let mut savings = Vec::with_capacity(config.savings_locks.len());
    for lock in &config.savings_locks {
        savings.push(kit::KitSavings {
            unlock: lock.unlock,
            address: lock.address.clone(),
            descriptor: lock.policy(network)?.descriptor.to_string(),
            default_deposit: lock.default_deposit,
            uses_earlier_phone_key: lock.phone_vault_pubkey != config.phone_vault_pubkey,
            heir: config
                .heir
                .as_ref()
                .is_some_and(|heir| lock.heir_vault_pubkey.as_ref() == Some(&heir.vault_pubkey)),
            yubikey: lock.yubikey_vault_pubkey.is_some(),
        });
    }
    let backup_path = data_dir.join(core::storage::PHONE_BACKUP_FILE);
    let friends = if backup_path.exists() {
        let backup: core::social::CloudRecoveryBackup = core::storage::read_json(&backup_path)?;
        backup
            .friends
            .iter()
            .map(|friend| kit::KitFriend {
                name: core::social::friend_user_id(friend.public_key_armored.as_bytes()),
                fingerprint: friend.fingerprint.clone(),
            })
            .collect()
    } else {
        Vec::new()
    };
    let now = chrono::Utc::now().timestamp();
    let history = health::load_history(data_dir)?;
    let health = health::Device::ALL
        .into_iter()
        .map(|device| {
            (
                device,
                health::device_health(&config, &history, device, now),
            )
        })
        .collect();
    let html = kit::render(&kit::KitInput {
        owner,
        generated_at: now,
        network,
        vault_descriptor: config.vault_descriptor.clone(),
        vault_address: config.vault_address.clone(),
        phone_recovery_blocks: config.phone_recovery_blocks,
        hww_recovery_blocks: config.hww_recovery_blocks,
        monthly_limit_sats: config.monthly_limit_sats,
        emergency_access_limit_sats: config.emergency_access_limit_sats,
        savings,
        friends,
        health,
        heir: config.heir.as_ref().map(|heir| kit::KitHeir {
            name: heir.name.clone(),
            key: heir.vault_pubkey.clone(),
            recovery_blocks: core::HEIR_RECOVERY_BLOCKS,
        }),
        yubikey: config.yubikey_vault_pubkey.clone(),
    });
    fs::write(output, html).with_context(|| format!("failed to write {}", output.display()))?;
    println!("Recovery kit written: {}", output.display());
    println!(
        "It holds no keys and cannot move coins, but it shows where they are. Keep it private."
    );
    println!("Print it (or save it as PDF) and fill in page 5 by hand.");
    Ok(())
}

fn format_unix_date_i64(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0).map_or_else(
        || timestamp.to_string(),
        |date| date.format("%Y-%m-%d").to_string(),
    )
}

fn run_savings(data_dir: &Path, command: SavingsCommand) -> Result<()> {
    let mut config = core::storage::load_config(data_dir)?;
    match command {
        SavingsCommand::Create { unlock, default } => {
            let unlock = parse_unlock_date(&unlock)?;
            let lock = core::savings::add_lock(
                &mut config,
                unlock,
                chrono::Utc::now().timestamp(),
                default,
            )?;
            core::storage::save_config(data_dir, &config)?;
            println!("Savings lock created");
            print_savings_lock(&lock, &config)?;
        }
        SavingsCommand::List => {
            if config.savings_locks.is_empty() {
                println!(
                    "No savings locks. Create one with: anzen savings create --unlock YYYY-MM-DD"
                );
            }
            for lock in &config.savings_locks {
                print_savings_lock(lock, &config)?;
            }
        }
    }
    Ok(())
}

/// A savings unlock date: 00:00 UTC on a YYYY-MM-DD day.
fn parse_unlock_date(text: &str) -> Result<u32> {
    let date = chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d")
        .with_context(|| format!("invalid unlock date {text}; use YYYY-MM-DD"))?;
    let timestamp = date
        .and_hms_opt(0, 0, 0)
        .context("invalid unlock time")?
        .and_utc()
        .timestamp();
    u32::try_from(timestamp).context("unlock date is out of range")
}

fn format_unix_date(timestamp: u32) -> String {
    chrono::DateTime::from_timestamp(i64::from(timestamp), 0).map_or_else(
        || timestamp.to_string(),
        |date| date.format("%Y-%m-%d").to_string(),
    )
}

fn print_savings_lock(
    lock: &core::savings::SavingsLock,
    config: &core::storage::VaultConfig,
) -> Result<()> {
    let policy = lock.policy(config.bitcoin_network()?)?;
    println!("Unlocks: {}", format_unix_date(lock.unlock));
    println!("Address: {}", lock.address);
    println!("Descriptor: {}", policy.descriptor_string());
    println!(
        "Phone-only recovery from: {}",
        format_unix_date(lock.unlock + core::policy::SAVINGS_PHONE_RECOVERY_SECS)
    );
    println!(
        "HWW-only recovery from: {}",
        format_unix_date(lock.unlock + core::policy::SAVINGS_HWW_RECOVERY_SECS)
    );
    if let Some(heir) = &config.heir {
        if lock.heir_vault_pubkey.as_ref() == Some(&heir.vault_pubkey) {
            println!(
                "{}'s key from: {}",
                heir.name,
                format_unix_date(lock.unlock + core::policy::SAVINGS_HEIR_RECOVERY_SECS)
            );
        } else {
            println!(
                "{}'s key: none (created before the heir was named)",
                heir.name
            );
        }
    }
    if lock.default_deposit {
        println!("Default deposit address: yes");
    }
    Ok(())
}

fn print_deposit_address(data_dir: &Path) -> Result<()> {
    let config = core::storage::load_config(data_dir)?;
    match core::savings::deposit_target(&config) {
        core::savings::DepositTarget::Savings(lock) => {
            lock.policy(config.bitcoin_network()?)?;
            println!("Deposit address: {}", lock.address);
            println!(
                "Savings lock until {}: no ceremony needed, nothing can move it before then.",
                format_unix_date(lock.unlock)
            );
        }
        core::savings::DepositTarget::Vault(address) => {
            println!("Deposit address: {address}");
            println!(
                "Vault deposit: include it in an HWW ceremony within about 14 months. Create a savings lock to avoid that."
            );
        }
    }
    Ok(())
}

fn print_coins(data_dir: &Path, rpc_args: &ChainArgs, reveal: bool) -> Result<()> {
    use core::savings::{CoinPot, CoinStatus};
    let config = core::storage::load_config(data_dir)?;
    let network = config.bitcoin_network()?;
    let backend = rpc_args.connect_chain(data_dir)?;
    let tip = backend.chain_tip()?;
    let vault = backend.scan_vault(&config)?;
    let mut savings = Vec::with_capacity(config.savings_locks.len());
    for lock in &config.savings_locks {
        let address = lock.address(network)?;
        savings.push((lock.clone(), backend.scan_savings(&address)?));
    }
    let coins = core::savings::coin_ages(&config, &tip, &vault, &savings)?;
    if coins.is_empty() {
        println!("No vault or savings coins yet.");
    }
    for (index, coin) in coins.iter().enumerate() {
        let pot = match coin.pot {
            CoinPot::Vault => "Vault".to_owned(),
            CoinPot::Savings { unlock } => format!("Savings until {}", format_unix_date(unlock)),
        };
        let amount = if reveal {
            format!("{} sats", coin.value_sats)
        } else {
            "hidden".to_owned()
        };
        println!("Coin {} · {pot} · {amount}", index + 1);
        if reveal {
            println!("  ID: {}", coin.outpoint);
        }
        let days = coin.status.days_left().unwrap_or_default();
        let line = match coin.status {
            CoinStatus::Protected { .. } => {
                format!("Safe: needs phone + HWW. Phone-only recovery opens in ~{days} days.")
            }
            CoinStatus::CeremonyDue { .. } => format!(
                "Ceremony due: phone-only recovery opens in ~{days} days. Renew or run an HWW ceremony."
            ),
            CoinStatus::RecoveryOpen { .. } => {
                "Recovery open: the phone key alone can move it. Run an HWW ceremony now."
                    .to_owned()
            }
            CoinStatus::Locked { .. } => {
                format!("Locked: nobody can move it for ~{days} days. No ceremony needed.")
            }
            CoinStatus::Unlocked { phone_recovery_at } => format!(
                "Unlocked: phone + HWW can move it. Phone-only recovery opens {}.",
                format_unix_date(phone_recovery_at)
            ),
            CoinStatus::SavingsRecoveryOpen { .. } => {
                "Recovery open: the phone key alone can move it. Move it with phone + HWW."
                    .to_owned()
            }
        };
        println!("  {line}");
    }
    Ok(())
}

fn print_status(data_dir: &Path, rpc_args: &ChainArgs) -> Result<()> {
    let config = core::storage::load_config(data_dir)?;
    let backend = rpc_args.connect_chain(data_dir)?;
    let tip = backend.chain_tip()?;
    let utxos = backend.scan_vault(&config)?;
    let connectors = backend.scan_connectors(&config)?;
    let balance = utxos
        .iter()
        .map(|utxo| utxo.txout.value.to_sat())
        .sum::<u64>();
    println!("Network: {}", config.network);
    if tip.network == Network::Bitcoin {
        println!("Chain backend: {}", backend.backend_description());
    }
    println!("Height: {}", tip.height);
    println!("Median time past: {}", tip.median_time);
    println!("Vault UTXOs: {}", utxos.len());
    println!("Vault balance: {} sats", balance);
    println!("Live policy controller outputs: {}", connectors.len());
    if let Ok(schedule) = hot_wallet::load_schedule(data_dir) {
        let months = hot_wallet::live_rungs_for(&config, backend.as_ref(), &schedule)?;
        let unlocked = months
            .iter()
            .filter(|rung| core::ladder::is_unlocked(&rung.entry, tip.median_time))
            .count();
        println!(
            "Allowance months waiting: {} ({} unlocked, {} sats)",
            months.len(),
            unlocked,
            months.iter().map(|rung| rung.entry.value_sats).sum::<u64>()
        );
    }
    println!(
        "Monthly spending: {}",
        if config.monthly_limit_sats == 0 {
            "disabled".to_owned()
        } else {
            format!("{} sats", config.monthly_limit_sats)
        }
    );
    println!(
        "Emergency access: {}",
        if config.emergency_access_limit_sats == 0 {
            "disabled".to_owned()
        } else {
            format!("{} sats", config.emergency_access_limit_sats)
        }
    );
    if let Some(oldest) = utxos.first() {
        println!("Oldest confirmation height: {}", oldest.confirmation_height);
        print_recovery_activation(
            "Phone",
            oldest.confirmation_height + u64::from(config.phone_recovery_blocks),
            tip.height + 1,
            tip.median_time,
        );
        print_recovery_activation(
            "HWW",
            oldest.confirmation_height + u64::from(config.hww_recovery_blocks),
            tip.height + 1,
            tip.median_time,
        );
        if config.heir.is_some() {
            print_recovery_activation(
                "Heir",
                oldest.confirmation_height + u64::from(core::HEIR_RECOVERY_BLOCKS),
                tip.height + 1,
                tip.median_time,
            );
        }
    }
    Ok(())
}

fn ask_words(prompt: &str) -> Result<String> {
    eprint!("{prompt}: ");
    io::stderr().flush()?;
    let mut words = String::new();
    io::stdin().read_line(&mut words)?;
    Ok(words.trim().to_owned())
}

fn run_simple(
    command: SimpleCommand,
    data_dir: &Path,
    rpc_args: &ChainArgs,
    network: Network,
) -> Result<()> {
    if let SimpleCommand::Init {
        words,
        rescue_paper,
        every,
    } = command
    {
        let words = match words {
            Some(words) => words,
            None => ask_words("Type your 12 words")?,
        };
        let init = simple_wallet::initialize(data_dir, network, &words, rescue_paper, every)?;
        println!("Simple mode set up ({})", network_label(network));
        println!("Payouts open {}", every.label());
        println!("Deposit address: {}", init.inbox);
        if let Some(rescue) = &init.rescue_words {
            println!();
            println!("RESCUE PAPER: write these 12 words on paper now. They are shown only once.");
            println!("  {rescue}");
            println!(
                "Keep the paper somewhere other than your 12 words. With both, you can move every \
                 payout at any time; the paper alone cannot move anything."
            );
        } else {
            println!(
                "No rescue paper: someone who copies your 12 words can take each payout as it opens."
            );
        }
        println!();
        println!(
            "Your Fedi balance is spending money. These payouts are your savings: nothing, not \
             even you, can open one before its date."
        );
        return Ok(());
    }

    let config = simple_wallet::load_config(data_dir)?;
    let backend = rpc_args.connect_chain_for(config.bitcoin_network()?)?;
    match command {
        SimpleCommand::Init { .. } => unreachable!("handled above"),
        SimpleCommand::Inbox => {
            let coins = simple_wallet::inbox_coins(data_dir, &*backend)?;
            println!("Deposit address: {}", config.inbox()?.address);
            println!(
                "Waiting to be locked: {} sats in {} coin(s)",
                coins
                    .iter()
                    .map(|coin| coin.txout.value.to_sat())
                    .sum::<u64>(),
                coins.len()
            );
        }
        SimpleCommand::Lock {
            amount,
            accept_high_fees,
        } => {
            let median = backend.chain_tip()?.median_time;
            let now = u32::try_from(chrono::Utc::now().timestamp().max(median as i64))
                .context("clock is out of range")?;
            let plan = simple_wallet::lock(data_dir, &*backend, amount, now, accept_high_fees)?;
            println!(
                "Locked into {} payout(s): {}",
                plan.payouts.len(),
                plan.txid
            );
            for (index, payout) in plan.payouts.iter().enumerate() {
                println!(
                    "  Payout {:>2}  opens {}  {} sats",
                    index + 1,
                    core::ladder::unlock_date(payout.unlock),
                    payout.value_sats
                );
            }
            println!("Fee: {} sats", plan.fee_sats);
            println!(
                "Estimated fees to set up and claim these: about {:.1}% of the savings a year",
                plan.yearly_fee_percent
            );
        }
        SimpleCommand::Payouts => {
            let statuses = simple_wallet::payout_statuses(data_dir, &*backend)?;
            if statuses.is_empty() {
                println!(
                    "No payouts yet. Deposit to the inbox, then: anzen simple lock --amount <sats>"
                );
            }
            for status in statuses {
                let state = match (status.live, status.open) {
                    (false, _) => "moved",
                    (true, true) => "open: anzen simple claim --to <address>",
                    (true, false) => "locked",
                };
                println!(
                    "  {}  {} sats  {state}",
                    core::ladder::unlock_date(status.payout.unlock),
                    status.payout.value_sats
                );
            }
        }
        SimpleCommand::Claim { to } => {
            let destination = simple_wallet::parse_address(&config, &to)?;
            let result = simple_wallet::claim(data_dir, &*backend, &destination)?;
            println!("Claimed {} payout(s): {}", result.payout_count, result.txid);
            println!("Sent: {} sats to {destination}", result.sent_sats);
            println!("Fee: {} sats", result.fee_sats);
        }
        SimpleCommand::Rescue { to, rescue_words } => {
            let destination = simple_wallet::parse_address(&config, &to)?;
            let words = match rescue_words {
                Some(words) => words,
                None => ask_words("Type the 12 words on your rescue paper")?,
            };
            let result = simple_wallet::rescue(data_dir, &*backend, &words, &destination)?;
            println!("Rescued {} payout(s): {}", result.payout_count, result.txid);
            println!("Sent: {} sats to {destination}", result.sent_sats);
            println!("Fee: {} sats", result.fee_sats);
        }
    }
    Ok(())
}

fn run_node(command: NodeCommand, rpc_args: &ChainArgs, network: Network) -> Result<()> {
    if network != Network::Regtest {
        bail!("vault node commands are unavailable in mainnet mode");
    }
    let rpc = rpc_args.connect_core(Network::Regtest)?;
    match command {
        NodeCommand::Info => {
            let info = rpc.chain_info()?;
            println!("Network: {}", info.chain);
            println!("Height: {}", info.blocks);
            println!("Median time past: {}", info.median_time);
            println!("Best block: {}", info.best_block_hash);
        }
        NodeCommand::SetTime { timestamp } => {
            rpc.set_mock_time(timestamp)?;
            println!("Regtest mock time set to {timestamp}");
        }
        NodeCommand::Mine { blocks, address } => {
            let address = address
                .parse::<bitcoin::Address<_>>()?
                .require_network(Network::Regtest)?;
            let hashes = rpc.mine(blocks, &address)?;
            println!("Mined {} blocks", hashes.len());
            if let Some(hash) = hashes.last() {
                println!("New tip: {hash}");
            }
        }
    }
    Ok(())
}

fn print_manifest(manifest: &core::ceremony::BatchManifest, stderr: bool) -> Result<()> {
    let mut output: Box<dyn Write> = if stderr {
        Box::new(io::stderr().lock())
    } else {
        Box::new(io::stdout().lock())
    };
    writeln!(output, "PHONE POLICY PROPOSAL")?;
    writeln!(
        output,
        "Cold storage descriptor: {}",
        manifest.vault_descriptor
    )?;
    writeln!(output, "Vault address: {}", manifest.vault_address)?;
    writeln!(
        output,
        "Policy controller address: {}",
        manifest.controller_address
    )?;
    writeln!(
        output,
        "Emergency connector reserve: {} sats",
        manifest.connector_value_sats
    )?;
    if manifest.monthly_limit_sats == 0 {
        writeln!(output, "Monthly spending: disabled")?;
    } else {
        writeln!(
            output,
            "Monthly limit: {} sats",
            manifest.monthly_limit_sats
        )?;
    }
    if manifest.emergency_access_limit_sats == 0 {
        writeln!(output, "Emergency access: disabled")?;
    } else {
        writeln!(
            output,
            "Emergency access limit: {} sats",
            manifest.emergency_access_limit_sats
        )?;
        writeln!(
            output,
            "Emergency access delay: {} seconds (~1 week)",
            core::EMERGENCY_ACCESS_DELAY_SECONDS
        )?;
    }
    writeln!(output, "Fee rate: {} sat/vB", manifest.fee_rate_sat_vb)?;
    writeln!(output, "Total input: {} sats", manifest.total_input_sats)?;
    writeln!(output, "Allowance months: {}", manifest.allowance_count)?;
    for rung in &manifest.rungs {
        writeln!(
            output,
            "  Month {:>2}  unlocks {}  {} sats  {}",
            rung.step,
            core::ladder::unlock_date(rung.unlock),
            rung.value_sats,
            rung.address
        )?;
    }
    if manifest.allowance_count < core::MONTHS_PER_ROLLOVER && manifest.monthly_limit_sats > 0 {
        writeln!(
            output,
            "WARNING: balance funds only {} of {} monthly allowances",
            manifest.allowance_count,
            core::MONTHS_PER_ROLLOVER
        )?;
    }
    if manifest.has_presigned_renewal {
        writeln!(
            output,
            "Presigned renewal: second year included, broadcast after {} seconds (~360 days)",
            core::PRESIGNED_RENEWAL_DELAY_SECONDS
        )?;
    }
    writeln!(output, "Rollover txid: {}", manifest.rollover.unsigned_txid)?;
    writeln!(output, "Rollover fee: {} sats", manifest.rollover.fee_sats)?;
    if manifest.allowance_count > 0 {
        writeln!(
            output,
            "Allowance total: {} sats",
            manifest.allowance_value_sats
        )?;
        writeln!(
            output,
            "Back to the vault: {} sats",
            manifest.remainder_value_sats
        )?;
    }
    if let Some(emergency) = &manifest.emergency_access {
        writeln!(
            output,
            "Emergency trigger txid: {}",
            emergency.trigger.unsigned_txid
        )?;
        writeln!(
            output,
            "Emergency withdrawal txid: {}",
            emergency.withdrawal.unsigned_txid
        )?;
        writeln!(output, "Emergency hot address: {}", emergency.hot_address)?;
    }
    writeln!(
        output,
        "Phone signed PSBTs: {}",
        core::ceremony::manifest_transactions(manifest).len()
    )?;
    Ok(())
}

fn report_sweep(package: &core::recovery::CooperativeSweepPackage, stderr: bool) -> Result<()> {
    let mut output: Box<dyn Write> = if stderr {
        Box::new(io::stderr().lock())
    } else {
        Box::new(io::stdout().lock())
    };
    writeln!(output, "COOPERATIVE VAULT SWEEP")?;
    writeln!(output, "Destination: {}", package.destination)?;
    writeln!(output, "Inputs: {}", package.input_count)?;
    writeln!(output, "Sent: {} sats", package.sent_sats)?;
    writeln!(output, "Fee: {} sats (1 sat/vB)", package.fee_sats)?;
    writeln!(output, "Phone signed: {}", package.phone_approved)?;
    if package.hww_approved {
        writeln!(output, "HWW signed: true")?;
    }
    Ok(())
}

fn report_pair_sweep(package: &core::recovery::PairSweepPackage, stderr: bool) -> Result<()> {
    let mut output: Box<dyn Write> = if stderr {
        Box::new(io::stderr().lock())
    } else {
        Box::new(io::stdout().lock())
    };
    let (title, signed) = match package.path {
        core::recovery::SweepPath::PhoneYubikey => {
            ("VAULT SWEEP WITH PHONE + YUBIKEY", "Phone signed: true")
        }
        _ => (
            "VAULT SWEEP WITH HARDWARE WALLET + YUBIKEY",
            "Hardware wallet signed: true",
        ),
    };
    writeln!(output, "{title}")?;
    writeln!(output, "Destination: {}", package.destination)?;
    writeln!(output, "Coins: {}", package.input_count)?;
    writeln!(output, "Sent: {} sats", package.sent_sats)?;
    writeln!(output, "Fee: {} sats (1 sat/vB)", package.fee_sats)?;
    writeln!(output, "{signed}")?;
    Ok(())
}

fn report_savings_spend(
    package: &core::savings_spend::SavingsSpendPackage,
    stderr: bool,
) -> Result<()> {
    let mut output: Box<dyn Write> = if stderr {
        Box::new(io::stderr().lock())
    } else {
        Box::new(io::stdout().lock())
    };
    writeln!(output, "SAVINGS SPEND")?;
    writeln!(output, "Savings lock: {}", format_unix_date(package.unlock))?;
    writeln!(output, "Destination: {}", package.destination)?;
    writeln!(output, "Coins: {}", package.input_count)?;
    writeln!(output, "Sent: {} sats", package.sent_sats)?;
    writeln!(
        output,
        "Fee: {} sats ({} sat/vB)",
        package.fee_sats, package.fee_rate_sat_vb
    )?;
    writeln!(output, "Phone signed: {}", package.phone_approved)?;
    if package.hww_approved {
        writeln!(output, "HWW signed: true")?;
    }
    Ok(())
}

fn report_rotation(package: &core::recovery::PhoneRotationPackage, stderr: bool) -> Result<()> {
    let mut output: Box<dyn Write> = if stderr {
        Box::new(io::stderr().lock())
    } else {
        Box::new(io::stdout().lock())
    };
    writeln!(output, "PHONE-KEY ROTATION")?;
    writeln!(
        output,
        "New phone vault key: {}",
        package.new_phone_vault_pubkey
    )?;
    writeln!(
        output,
        "New cold storage descriptor: {}",
        package.new_vault_descriptor
    )?;
    writeln!(output, "New vault address: {}", package.new_vault_address)?;
    writeln!(output, "Inputs: {}", package.sweep.input_count)?;
    writeln!(output, "Sent: {} sats", package.sweep.sent_sats)?;
    writeln!(output, "Fee: {} sats (1 sat/vB)", package.sweep.fee_sats)?;
    if let Some(policy) = &package.renewed_policy {
        writeln!(
            output,
            "Monthly policy preserved: {} sats",
            policy.manifest.monthly_limit_sats
        )?;
        writeln!(
            output,
            "Renewed allowance months: {}",
            policy.manifest.allowance_count
        )?;
        writeln!(
            output,
            "Renewed policy transactions: {}",
            core::ceremony::manifest_transactions(&policy.manifest).len()
        )?;
        if policy.manifest.emergency_access_limit_sats > 0 {
            writeln!(
                output,
                "Emergency access preserved: {} sats",
                policy.manifest.emergency_access_limit_sats
            )?;
        }
    } else {
        writeln!(output, "Programmable vault policy remains disabled")?;
    }
    Ok(())
}

/// The allowance months the HWW can still pull back: those it approved, plus any the phone's
/// schedule in this folder lists, that are still unspent and belong to the current keys.
fn hww_live_months(
    data_dir: &Path,
    config: &core::storage::VaultConfig,
    backend: &dyn core::chain::Blockchain,
) -> Result<Vec<core::ladder::LiveRung>> {
    let mut entries = cold_wallet::approved_rungs(data_dir)?;
    let schedule_path = data_dir.join(core::ceremony::SCHEDULE_FILE);
    if let Ok(schedule) = core::storage::read_json::<core::ceremony::Schedule>(&schedule_path) {
        for entry in schedule
            .previous_entries
            .into_iter()
            .chain(schedule.entries)
        {
            if !entries.iter().any(|known| known.outpoint == entry.outpoint) {
                entries.push(entry);
            }
        }
    }
    let mut live = Vec::new();
    for entry in &entries {
        // Months approved under an earlier phone key cannot match this vault's keys.
        let Ok(rung) = core::ladder::LiveRung::new(config, entry) else {
            continue;
        };
        if backend
            .scan_savings(&rung.policy.address)?
            .iter()
            .any(|coin| coin.outpoint == entry.outpoint)
        {
            live.push(rung);
        }
    }
    Ok(live)
}

fn hww_banner(data_dir: &Path, title: &str) {
    if cold_wallet::ledger::is_ledger_hww(data_dir) {
        eprintln!("LEDGER — {title}");
    } else if cold_wallet::bitbox::is_bitbox_hww(data_dir) {
        eprintln!("BITBOX02 — {title}");
    } else {
        eprintln!("SIMULATED HWW — {title}");
    }
}

fn require_hww_approval(yes: bool, input: &Path, description: &str) -> Result<()> {
    require_approval(yes, input, description, "HWW")
}

fn require_approval(yes: bool, input: &Path, description: &str, device: &str) -> Result<()> {
    if yes {
        return Ok(());
    }
    if input == Path::new("-") {
        bail!("--yes is required when the proposal is read from stdin");
    }
    print!("Type `approve` to confirm the {description}: ");
    io::stdout().flush()?;
    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    if response.trim() != "approve" {
        bail!("{device} approval declined");
    }
    Ok(())
}

fn print_sweep_result(label: &str, result: &core::recovery::SweepResult) {
    println!("{label}: {}", result.txid);
    println!("Inputs: {}", result.input_count);
    println!("Sent: {} sats", result.sent_sats);
    println!("Fee: {} sats (1 sat/vB)", result.fee_sats);
}

fn print_spend_result(label: &str, result: &core::recovery::SweepResult, fee_rate: u64) {
    println!("{label}: {}", result.txid);
    println!("Coins: {}", result.input_count);
    println!("Sent: {} sats", result.sent_sats);
    println!("Fee: {} sats ({fee_rate} sat/vB)", result.fee_sats);
}

/// For spends whose fee rate was fetched live and is not stored in a package.
fn print_sweep_result_line(label: &str, result: &core::recovery::SweepResult) {
    println!("{label}: {}", result.txid);
    println!("Coins: {}", result.input_count);
    println!("Sent: {} sats", result.sent_sats);
    println!("Fee: {} sats", result.fee_sats);
}

fn reset_workspace(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)
            .with_context(|| format!("failed to reset workspace {}", path.display()))?;
    }
    Ok(())
}

fn read_artifact<T: DeserializeOwned>(path: &Path) -> Result<T> {
    if path == Path::new("-") {
        serde_json::from_reader(io::stdin().lock())
            .context("failed to read JSON artifact from stdin")
    } else {
        core::storage::read_json(path)
    }
}

fn write_artifact<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if path == Path::new("-") {
        let mut stdout = io::stdout().lock();
        serde_json::to_writer_pretty(&mut stdout, value)?;
        writeln!(stdout)?;
        Ok(())
    } else {
        core::storage::write_json(path, value)
    }
}

fn artifact_reports_to_stderr(path: &Path) -> bool {
    path == Path::new("-")
}

fn report_artifact(path: &Path, description: &str) -> Result<()> {
    if path != Path::new("-") {
        println!("{description}: {}", path.display());
    }
    Ok(())
}

fn configured_address(data_dir: &Path, text: &str) -> Result<bitcoin::Address> {
    use std::str::FromStr;
    let config = core::storage::load_config(data_dir)?;
    bitcoin::Address::from_str(text)?
        .require_network(config.bitcoin_network()?)
        .map_err(Into::into)
}

fn command_network(
    data_dir: &Path,
    dangerously_enable_mainnet: bool,
    signet: bool,
    _command: &Command,
) -> Result<Network> {
    let configured = if simple_wallet::is_initialized(data_dir) {
        Some(simple_wallet::load_config(data_dir)?.bitcoin_network()?)
    } else if core::storage::config_exists(data_dir) {
        Some(core::storage::load_config(data_dir)?.bitcoin_network()?)
    } else if data_dir.join(core::storage::PHONE_DEVICE_FILE).exists() {
        Some(
            core::storage::load_device(data_dir, core::storage::PHONE_DEVICE_FILE)?
                .bitcoin_network()?,
        )
    } else if data_dir.join(core::storage::HWW_DEVICE_FILE).exists() {
        Some(
            core::storage::load_device(data_dir, core::storage::HWW_DEVICE_FILE)?
                .bitcoin_network()?,
        )
    } else if data_dir.join(core::storage::HWW_PUBLIC_FILE).exists() {
        Some(
            core::storage::load_public_device(data_dir, core::storage::HWW_PUBLIC_FILE)?
                .bitcoin_network()?,
        )
    } else if data_dir.join(core::storage::HEIR_PUBLIC_FILE).exists() {
        let heir: core::storage::HeirPublicFile =
            core::storage::read_json(&data_dir.join(core::storage::HEIR_PUBLIC_FILE))?;
        Some(core::storage::parse_network_name(&heir.network)?)
    } else if data_dir.join(core::storage::YUBIKEY_PUBLIC_FILE).exists() {
        let yubikey: core::storage::YubikeyPublicFile =
            core::storage::read_json(&data_dir.join(core::storage::YUBIKEY_PUBLIC_FILE))?;
        Some(core::storage::parse_network_name(&yubikey.network)?)
    } else if data_dir.join(core::watch::WATCH_PACKAGE_FILE).exists() {
        let package: core::watch::WatchPackage =
            core::storage::read_json(&data_dir.join(core::watch::WATCH_PACKAGE_FILE))?;
        Some(package.bitcoin_network()?)
    } else {
        None
    };

    match (configured, dangerously_enable_mainnet) {
        (Some(Network::Bitcoin), false) => {
            bail!("mainnet vault is locked; pass --dangerously-enable-mainnet on every command")
        }
        (Some(Network::Bitcoin), true) => Ok(Network::Bitcoin),
        (Some(Network::Regtest), true) => bail!(
            "vault is configured for regtest; --dangerously-enable-mainnet cannot change an existing vault"
        ),
        (Some(Network::Regtest), false) if !signet => Ok(Network::Regtest),
        (Some(Network::Signet), true) => bail!(
            "vault is configured for signet; --dangerously-enable-mainnet cannot change an existing vault"
        ),
        (Some(Network::Signet), false) => Ok(Network::Signet),
        (Some(other), _) if signet => {
            bail!("vault is configured for {other}; --signet cannot change an existing vault")
        }
        (Some(other), _) => bail!("unsupported vault network: {other}"),
        (None, true) => Ok(Network::Bitcoin),
        (None, false) if signet => Ok(Network::Signet),
        (None, false) => Ok(Network::Regtest),
    }
}

fn run_watch(
    command: WatchCommand,
    data_dir: &Path,
    rpc_args: &ChainArgs,
    network: Network,
) -> Result<()> {
    match command {
        WatchCommand::Export { output } => {
            let package = core::watch::load_package(data_dir)?;
            core::storage::write_json(&output, &package)?;
            println!("Watch plan written to {}", output.display());
            println!(
                "It holds descriptors and expected txids, no keys. Anyone who reads it can see \
                 your vault's balance and history, so keep it private."
            );
            println!(
                "On the watcher computer: anzen --data-dir <folder> watch import {}",
                output.display()
            );
            Ok(())
        }
        WatchCommand::Import { plan } => {
            let package: core::watch::WatchPackage = core::storage::read_json(&plan)?;
            if package.bitcoin_network()? != network {
                bail!(
                    "this watch plan is for {}; pass the matching network flag",
                    package.network
                );
            }
            core::watch::import_package(data_dir, &package)?;
            println!("Watch plan imported ({})", network_label(network));
            println!(
                "Savings locks watched: {}",
                package.savings_descriptors.len()
            );
            println!("Planned transactions known: {}", package.known.len());
            println!(
                "Start watching: anzen --data-dir {} watch run --every 60",
                data_dir.display()
            );
            Ok(())
        }
        WatchCommand::Run {
            every,
            notify_command,
            reveal,
        } => {
            let Some(every) = every else {
                return watch_once(
                    data_dir,
                    rpc_args,
                    network,
                    notify_command.as_deref(),
                    reveal,
                );
            };
            println!("Watching every {every} seconds. Stop with Ctrl-C.");
            let mut failures = 0u32;
            loop {
                match watch_once(
                    data_dir,
                    rpc_args,
                    network,
                    notify_command.as_deref(),
                    reveal,
                ) {
                    Ok(()) => {
                        if failures >= WATCH_FAILURES_BEFORE_ALERT {
                            notify_or_warn(
                                notify_command.as_deref(),
                                core::watch::Level::Info,
                                "Watcher reconnected",
                                "The watcher can read the chain again.",
                            );
                        }
                        failures = 0;
                    }
                    Err(error) => {
                        failures += 1;
                        eprintln!("Watch check failed: {error:#}");
                        if failures == WATCH_FAILURES_BEFORE_ALERT {
                            notify_or_warn(
                                notify_command.as_deref(),
                                core::watch::Level::Notice,
                                "Watcher cannot reach the chain",
                                "The watcher has failed several checks in a row, so it cannot \
                                 see vault moves right now. Check its node or Electrum server.",
                            );
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(every));
            }
        }
    }
}

/// Consecutive failed checks before the watcher tells the owner it is blind.
const WATCH_FAILURES_BEFORE_ALERT: u32 = 3;

fn watch_once(
    data_dir: &Path,
    rpc_args: &ChainArgs,
    network: Network,
    notify_command: Option<&str>,
    reveal: bool,
) -> Result<()> {
    let package = core::watch::load_package(data_dir)?;
    if package.bitcoin_network()? != network {
        bail!("the watch plan is for {}", package.network);
    }
    let backend = rpc_args.connect_chain_for(network)?;
    let state_path = data_dir.join(core::watch::WATCH_STATE_FILE);
    let state = core::watch::WatchState::load(&state_path)?;
    let report = core::watch::poll(
        backend.as_ref(),
        &package,
        state,
        chrono::Utc::now().timestamp(),
    )?;
    for event in &report.events {
        println!(
            "[{}] {}",
            event.level.to_string().to_uppercase(),
            event.title
        );
        println!("  {}", event.message);
        if reveal {
            if let Some(txid) = event.txid {
                let state = if event.confirmed {
                    "confirmed"
                } else {
                    "in the mempool"
                };
                println!("  Transaction: {txid} ({state})");
            }
            if let Some(sats) = event.amount_sats {
                println!("  Coins involved: {} sats", format_number(sats));
            }
        }
    }
    // Save only once every alert is delivered, so a failed one is raised again next time.
    if let Some(command) = notify_command {
        for event in &report.events {
            notify(command, event.level, &event.title, &event.message)?;
        }
    }
    report.state.save(&state_path)?;
    if report.events.is_empty() {
        println!(
            "No changes. Watching {} coin(s) up to block {}.",
            report.coins_watched,
            format_number(report.height)
        );
    }
    Ok(())
}

fn notify(command: &str, level: core::watch::Level, title: &str, message: &str) -> Result<()> {
    use std::io::Write;
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .env("ANZEN_ALERT_LEVEL", level.to_string())
        .env("ANZEN_ALERT_TITLE", title)
        .env("ANZEN_ALERT_MESSAGE", message)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("could not start the notify command")?;
    if let Some(mut stdin) = child.stdin.take() {
        // A command that ignores stdin may close it early; that is fine.
        let _ = writeln!(stdin, "{title}\n\n{message}");
    }
    let status = child.wait().context("the notify command did not finish")?;
    if !status.success() {
        bail!("the notify command failed ({status}) for \"{title}\"");
    }
    Ok(())
}

fn notify_or_warn(command: Option<&str>, level: core::watch::Level, title: &str, message: &str) {
    println!("[{}] {title}", level.to_string().to_uppercase());
    println!("  {message}");
    if let Some(command) = command {
        if let Err(error) = notify(command, level, title, message) {
            eprintln!("{error:#}");
        }
    }
}

fn network_label(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "MAINNET — REAL FUNDS",
        Network::Regtest => "REGTEST ONLY",
        Network::Signet => "SIGNET (TEST COINS)",
        _ => "UNSUPPORTED NETWORK",
    }
}

fn print_recovery_activation(label: &str, valid_height: u64, next_height: u64, median_time: u64) {
    if next_height >= valid_height {
        println!("{label} recovery: ACTIVE (valid next-block height {valid_height})");
    } else {
        let remaining = valid_height - next_height;
        let estimated_timestamp = median_time.saturating_add(remaining.saturating_mul(600));
        let estimated = i64::try_from(estimated_timestamp)
            .ok()
            .and_then(|timestamp| chrono::DateTime::from_timestamp(timestamp, 0))
            .map(|date| date.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "outside displayable range".to_owned());
        println!(
            "{label} recovery: valid next-block height {valid_height} ({remaining} blocks remaining; estimated {estimated} at 10-minute blocks)"
        );
    }
}

fn format_number(value: u64) -> String {
    let digits = value.to_string();
    let mut formatted = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            formatted.push(',');
        }
        formatted.push(character);
    }
    formatted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_chain_args() -> ChainArgs {
        ChainArgs {
            chain_backend: None,
            rpc_url: None,
            rpc_user: "anzen".to_owned(),
            rpc_password: "anzen".to_owned(),
            electrum_url: None,
        }
    }

    #[test]
    fn chain_backend_defaults_can_be_overridden_on_either_network() {
        let mut args = default_chain_args();
        assert_eq!(
            args.selected_backend(Network::Regtest).unwrap(),
            ChainBackendKind::Rpc
        );
        assert_eq!(
            args.selected_backend(Network::Bitcoin).unwrap(),
            ChainBackendKind::Electrum
        );

        args.chain_backend = Some(ChainBackendKind::Electrum);
        assert_eq!(
            args.selected_backend(Network::Regtest).unwrap(),
            ChainBackendKind::Electrum
        );
        args.chain_backend = Some(ChainBackendKind::Rpc);
        assert_eq!(
            args.selected_backend(Network::Bitcoin).unwrap(),
            ChainBackendKind::Rpc
        );
    }
}
