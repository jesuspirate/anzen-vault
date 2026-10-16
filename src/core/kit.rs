//! The printable recovery kit.
//!
//! One self-contained HTML document, laid out as printed pages, that explains the vault to the
//! people who will need it most and know it least: an heir, a recovery friend, or the owner years
//! from now. It is written in plain language with pictures first and technical detail last.
//!
//! The kit contains public information only (descriptors, addresses, dates, friend fingerprints).
//! It cannot move coins. It does reveal where the coins are, so it is private.

use super::{
    health::{Device, DeviceHealth},
    policy::{SAVINGS_HWW_RECOVERY_SECS, SAVINGS_PHONE_RECOVERY_SECS},
};
use bitcoin::Network;
use std::fmt::Write as _;

#[derive(Debug, Clone)]
pub struct KitSavings {
    pub unlock: u32,
    pub address: String,
    pub descriptor: String,
    pub default_deposit: bool,
    /// The lock was created with a phone key the vault no longer uses.
    pub uses_earlier_phone_key: bool,
}

#[derive(Debug, Clone)]
pub struct KitFriend {
    pub name: Option<String>,
    pub fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct KitInput {
    pub owner: Option<String>,
    pub generated_at: i64,
    pub network: Network,
    pub vault_descriptor: String,
    pub vault_address: String,
    pub phone_recovery_blocks: u16,
    pub hww_recovery_blocks: u16,
    pub monthly_limit_sats: u64,
    pub emergency_access_limit_sats: u64,
    pub savings: Vec<KitSavings>,
    pub friends: Vec<KitFriend>,
    pub health: Vec<(Device, DeviceHealth)>,
}

/// Blocks arrive about every ten minutes, so 144 blocks is about a day.
fn blocks_to_days(blocks: u16) -> u64 {
    u64::from(blocks).div_ceil(144)
}

fn months_label(days: u64) -> String {
    format!("about {} months", (days as f64 / 30.44).round() as u64)
}

fn capitalize(text: &str) -> String {
    let mut characters = text.chars();
    characters.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(characters).collect()
    })
}

fn date(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0).map_or_else(
        || timestamp.to_string(),
        |date| date.format("%B %-d, %Y").to_string(),
    )
}

fn btc(sats: u64) -> String {
    let whole = sats / 100_000_000;
    let fraction = sats % 100_000_000;
    if fraction == 0 {
        return format!("{whole} BTC");
    }
    let fraction = format!("{fraction:08}");
    format!("{whole}.{} BTC", fraction.trim_end_matches('0'))
}

fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

const STYLE: &str = r#"
:root{--ink:#1b2430;--soft:#4f5b6b;--line:#cfd6df;--paper:#ffffff;--wash:#f2f5f8;
--vault:#1f5f8b;--vault-wash:#e3eef6;--save:#7a4f12;--save-wash:#f6ecdc;--ok:#256b3e;--ok-wash:#e2f1e7;
--warn:#9a3b1c;--warn-wash:#f8e4dc;color-scheme:light}
*{box-sizing:border-box}
html,body{background:var(--paper);color:var(--ink)}
body{margin:0;font:16px/1.55 Georgia,"Iowan Old Style","Times New Roman",serif}
.page{max-width:52rem;margin:0 auto;padding:40px max(20px,env(safe-area-inset-left,0px)) 48px max(20px,env(safe-area-inset-right,0px));display:grid;gap:22px;break-after:page;page-break-after:always}
.page:last-child{break-after:auto;page-break-after:auto}
h1,h2,h3{font-family:"Helvetica Neue",Arial,sans-serif;line-height:1.2;margin:0;text-wrap:balance}
h1{font-size:2.3rem} h2{font-size:1.6rem;border-bottom:3px solid var(--ink);padding-bottom:8px} h3{font-size:1.1rem}
p{margin:0} ol,ul{margin:0;padding-left:1.4em;display:grid;gap:8px}
.label{font:700 .75rem/1 "Helvetica Neue",Arial,sans-serif;letter-spacing:.09em;text-transform:uppercase;color:var(--soft)}
.big{font-size:1.2rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr));gap:14px}
.box{border:2px solid var(--line);border-radius:10px;padding:16px;display:grid;gap:8px;break-inside:avoid}
.box.vault{border-color:var(--vault);background:var(--vault-wash)}
.box.save{border-color:var(--save);background:var(--save-wash)}
.box.ok{border-color:var(--ok);background:var(--ok-wash)}
.box.warn{border-color:var(--warn);background:var(--warn-wash)}
.situation{display:grid;grid-template-columns:3rem 1fr;gap:12px;align-items:start}
.letter{font:700 1.6rem/3rem "Helvetica Neue",Arial,sans-serif;width:3rem;height:3rem;border-radius:50%;text-align:center;background:var(--ink);color:var(--paper)}
.steps li{padding-left:4px}
.fill{display:grid;grid-template-columns:minmax(10rem,16rem) 1fr;border:2px solid var(--ink);border-radius:8px;overflow:hidden}
.fill div{padding:12px;border-bottom:1px solid var(--line);min-height:3.2rem}
.fill div:nth-child(odd){background:var(--wash);font-weight:700;font-family:"Helvetica Neue",Arial,sans-serif;font-size:.95rem}
.fill div:nth-last-child(-n+2){border-bottom:0}
code,.mono{font:.82rem/1.45 "SFMono-Regular",Menlo,Consolas,monospace;overflow-wrap:anywhere;word-break:break-all}
.mono{display:block;background:var(--wash);border:1px solid var(--line);border-radius:6px;padding:10px}
svg{max-width:100%;height:auto;display:block}
svg text{font-family:"Helvetica Neue",Arial,sans-serif}
.note{font-size:.92rem;color:var(--soft)}
.pill{display:inline-block;font:700 .75rem/1 "Helvetica Neue",Arial,sans-serif;padding:5px 9px;border-radius:99px;letter-spacing:.04em}
.pill.ok{background:var(--ok-wash);color:var(--ok)} .pill.warn{background:var(--warn-wash);color:var(--warn)}
table{border-collapse:collapse;width:100%} th,td{text-align:left;vertical-align:top;padding:8px;border-bottom:1px solid var(--line)}
.scroll{overflow-x:auto}
@media (max-width:520px){h1{font-size:1.8rem}.fill{grid-template-columns:1fr}.fill div:nth-child(odd){border-bottom:0;min-height:auto;padding-bottom:4px}}
@page{margin:14mm}
@media print{.page{padding:0;max-width:none}}
"#;

const PHONE_ICON: &str = r##"<g><rect x="-18" y="-30" width="36" height="60" rx="7" fill="#ffffff" stroke="#1b2430" stroke-width="3"/><rect x="-12" y="-22" width="24" height="38" rx="2" fill="#e3eef6"/><circle cx="0" cy="23" r="3" fill="#1b2430"/></g>"##;
const HWW_ICON: &str = r##"<g><rect x="-30" y="-17" width="60" height="34" rx="8" fill="#ffffff" stroke="#1b2430" stroke-width="3"/><rect x="-20" y="-9" width="26" height="18" rx="2" fill="#e3eef6"/><circle cx="17" cy="0" r="5" fill="#1b2430"/></g>"##;

fn big_picture(input: &KitInput) -> String {
    let savings = !input.savings.is_empty();
    let height = if savings { 330 } else { 230 };
    let mut svg = format!(
        r##"<svg viewBox="0 0 720 {height}" role="img" aria-label="Two keys, the phone and the hardware wallet, together open the vault">
<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#1b2430"/></marker></defs>
<g transform="translate(90,70)">{PHONE_ICON}</g>
<text x="90" y="128" text-anchor="middle" font-size="15" font-weight="700" fill="#1b2430">Key 1: the phone</text>
<text x="90" y="147" text-anchor="middle" font-size="13" fill="#4f5b6b">Anzen app, everyday use</text>
<g transform="translate(90,190)">{HWW_ICON}</g>
<text x="90" y="226" text-anchor="middle" font-size="15" font-weight="700" fill="#1b2430">Key 2: hardware wallet</text>
<path d="M150 80 C250 80 260 125 330 125" fill="none" stroke="#1b2430" stroke-width="3" marker-end="url(#arrow)"/>
<path d="M150 185 C250 185 260 135 330 135" fill="none" stroke="#1b2430" stroke-width="3" marker-end="url(#arrow)"/>
<text x="205" y="137" text-anchor="middle" font-size="14" font-weight="700" fill="#1b2430">BOTH</text>
<rect x="340" y="70" width="350" height="120" rx="14" fill="#e3eef6" stroke="#1f5f8b" stroke-width="3"/>
<text x="515" y="106" text-anchor="middle" font-size="20" font-weight="700" fill="#1f5f8b">The Vault</text>
<text x="515" y="132" text-anchor="middle" font-size="14" fill="#1b2430">Both keys together: open any time</text>
<text x="515" y="154" text-anchor="middle" font-size="14" fill="#1b2430">Only one key: opens after a long wait</text>
<text x="515" y="176" text-anchor="middle" font-size="13" fill="#4f5b6b">(phone: ~{} months, hardware wallet: ~{} months)</text>
"##,
        (blocks_to_days(input.phone_recovery_blocks) as f64 / 30.44).round(),
        (blocks_to_days(input.hww_recovery_blocks) as f64 / 30.44).round(),
    );
    if savings {
        let first = input
            .savings
            .iter()
            .map(|lock| lock.unlock)
            .min()
            .unwrap_or_default();
        let _ = write!(
            svg,
            r##"<rect x="340" y="215" width="350" height="100" rx="14" fill="#f6ecdc" stroke="#7a4f12" stroke-width="3"/>
<text x="515" y="249" text-anchor="middle" font-size="20" font-weight="700" fill="#7a4f12">Savings Lock{}</text>
<text x="515" y="274" text-anchor="middle" font-size="14" fill="#1b2430">Nobody can open it before its date,</text>
<text x="515" y="295" text-anchor="middle" font-size="14" fill="#1b2430">not even with both keys. First date: {}</text>
<text x="262" y="232" text-anchor="end" font-size="13" fill="#4f5b6b">after its date</text>
<path d="M245 150 C270 230 280 265 330 265" fill="none" stroke="#1b2430" stroke-width="3" stroke-dasharray="7 6" marker-end="url(#arrow)"/>
"##,
            if input.savings.len() > 1 { "s" } else { "" },
            esc(&date(i64::from(first))),
        );
    }
    svg.push_str("</svg>");
    svg
}

/// A horizontal timeline from a start point through the dates each door opens.
fn timeline(title: &str, color: &str, start: &str, stops: &[(String, String)]) -> String {
    let width = 720;
    let left = 40;
    let right = width - 40;
    let mut svg = format!(
        r##"<svg viewBox="0 0 {width} 150" role="img" aria-label="{}">
<line x1="{left}" y1="60" x2="{right}" y2="60" stroke="{color}" stroke-width="6" stroke-linecap="round"/>
<circle cx="{left}" cy="60" r="11" fill="{color}"/>
<text x="{left}" y="30" font-size="14" font-weight="700" fill="#1b2430">{}</text>
"##,
        esc(title),
        esc(start),
    );
    let span = right - left;
    for (index, (when, what)) in stops.iter().enumerate() {
        let x = left + span * (index as i32 + 1) / stops.len() as i32;
        let anchor = if index + 1 == stops.len() {
            "end"
        } else {
            "middle"
        };
        let _ = write!(
            svg,
            r##"<circle cx="{x}" cy="60" r="11" fill="#ffffff" stroke="{color}" stroke-width="5"/>
<text x="{x}" y="96" text-anchor="{anchor}" font-size="14" font-weight="700" fill="#1b2430">{}</text>
<text x="{x}" y="118" text-anchor="{anchor}" font-size="13" fill="#4f5b6b">{}</text>
"##,
            esc(when),
            esc(what),
        );
    }
    svg.push_str("</svg>");
    svg
}

fn health_line(device: Device, health: DeviceHealth) -> String {
    match health {
        DeviceHealth::NeverChecked => format!(
            r#"<li><strong>{}:</strong> <span class="pill warn">Not checked yet</span></li>"#,
            device.label()
        ),
        DeviceHealth::Healthy { checked_at, .. } => format!(
            r#"<li><strong>{}:</strong> <span class="pill ok">Working</span> last checked {}</li>"#,
            device.label(),
            esc(&date(checked_at))
        ),
        DeviceHealth::Due { checked_at, .. } => format!(
            r#"<li><strong>{}:</strong> <span class="pill warn">Check overdue</span> last checked {}</li>"#,
            device.label(),
            esc(&date(checked_at))
        ),
    }
}

pub fn render(input: &KitInput) -> String {
    let phone_days = blocks_to_days(input.phone_recovery_blocks);
    let hww_days = blocks_to_days(input.hww_recovery_blocks);
    let phone_wait = months_label(phone_days);
    let hww_wait = months_label(hww_days);
    let owner = input
        .owner
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty());
    let whose = owner.map_or_else(|| "this vault".to_owned(), |name| format!("{name}'s vault"));
    let printed = date(input.generated_at);
    let network_note = match input.network {
        Network::Bitcoin => String::new(),
        _ => r#"<div class="box warn"><strong>Test vault.</strong> This kit describes a regtest test vault that holds no real bitcoin.</div>"#.to_owned(),
    };

    let mut html = String::with_capacity(32_000);
    let _ = write!(
        html,
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Recovery Kit · {title}</title><style>{STYLE}</style></head><body>
"#,
        title = esc(&whose),
    );

    // Page 1: cover.
    let _ = write!(
        html,
        r#"<section class="page">
<div class="label">Bitcoin inheritance and recovery kit · printed {printed}</div>
<h1>How to get to {whose_html}</h1>
<p class="big">This kit explains, in plain words and pictures, how the bitcoin in {whose_html} can be reached if a device is lost, or if {person} can no longer do it themselves. Read it from the start. You do not need to understand Bitcoin to follow it.</p>
{network_note}
<div class="grid">
<div class="box ok"><h3>This kit cannot move money</h3><p>It holds no passwords and no secret words. Losing it does not put the bitcoin at risk.</p></div>
<div class="box warn"><h3>Keep it private</h3><p>It shows where the bitcoin is and how much is there. Store it with a will or in a safe, not on a shared computer.</p></div>
<div class="box"><h3>Print a new one when things change</h3><p>After a phone is replaced, a savings lock is added, or a recovery friend changes. The newest printed date wins.</p></div>
</div>
<div class="box"><h3>What is inside</h3><ol>
<li>The big picture: two keys and a vault</li>
<li>Which situation are you in?</li>
<li>When each door opens</li>
<li>Step by step, for each situation</li>
<li>Where things are kept (filled in by hand)</li>
<li>For a technical helper</li>
<li>Words used in this kit</li>
</ol></div>
</section>
"#,
        printed = esc(&printed),
        whose_html = esc(&whose),
        person = owner.map_or_else(|| "the owner".to_owned(), esc),
    );

    // Page 2: big picture.
    let mut money = String::new();
    if input.monthly_limit_sats > 0 {
        let _ = write!(
            money,
            "<li>Each month the phone can take out up to <strong>{}</strong> for spending. This is set up ahead of time and needs only the phone.</li>",
            btc(input.monthly_limit_sats)
        );
    }
    if input.emergency_access_limit_sats > 0 {
        let _ = write!(
            money,
            "<li>Once a year the phone can ask for an emergency amount of <strong>{}</strong>. It arrives one week later, and either device can cancel it during that week.</li>",
            btc(input.emergency_access_limit_sats)
        );
    }
    let _ = write!(
        html,
        r#"<section class="page">
<div class="label">1 · The big picture</div>
<h2>Two keys and a vault</h2>
<p>The bitcoin sits in a <strong>vault</strong>. It is not at a bank or a company: it is protected by the Bitcoin network itself, using two keys that only the family holds. Nobody else, including the makers of the app, can open it or stop it from being opened.</p>
{picture}
<ul>
<li><strong>Key 1 is a phone</strong> with the Anzen app.</li>
<li><strong>Key 2 is a hardware wallet</strong>: a small dedicated device, protected by a PIN code.</li>
<li><strong>With both keys</strong> the vault opens right away.</li>
<li><strong>With only one key</strong> it still opens, but only after a long wait: {phone_wait} with the phone, {hww_wait} with the hardware wallet. The wait protects against a thief who steals just one key. The clock restarts whenever the coins are moved, so the app shows the exact date for each coin.</li>
{money}
</ul>
</section>
"#,
        picture = big_picture(input),
    );

    // Page 3: situations.
    let friends_line = if input.friends.is_empty() {
        "No recovery friends were set up when this kit was printed, so this route is not available."
            .to_owned()
    } else {
        let names = input
            .friends
            .iter()
            .map(|friend| esc(friend.name.as_deref().unwrap_or("a recovery friend")))
            .collect::<Vec<_>>()
            .join(", ");
        format!("Recovery friends set up: {names}.")
    };
    let _ = write!(
        html,
        r#"<section class="page">
<div class="label">2 · Which situation are you in?</div>
<h2>Find your situation, then go to its steps</h2>
<div class="box situation"><div class="letter">A</div><div><h3>You have the phone and the hardware wallet</h3><p>The fastest case. Everything in the vault can be moved today. Savings locks open on their dates.</p><p class="note">You also need the phone's unlock code and the hardware wallet's PIN. Section 5 says where they are kept.</p></div></div>
<div class="box situation"><div class="letter">B</div><div><h3>You have the hardware wallet, but not the phone</h3><p>Still fast, if you can sign in to the cloud account where the phone's encrypted backup is kept. The hardware wallet unlocks that backup and rebuilds the phone key. Without the cloud backup, the hardware wallet alone opens the vault after {hww_wait}.</p></div></div>
<div class="box situation"><div class="letter">C</div><div><h3>You have the phone, but not the hardware wallet</h3><p>The phone alone opens the vault after {phone_wait}. Nothing can make that faster. That is the price of protection against theft.</p></div></div>
<div class="box situation"><div class="letter">D</div><div><h3>You have neither device, but you are a recovery friend</h3><p>A recovery friend holds a personal key that can unlock the phone's cloud backup. The vault then opens after {phone_wait}. {friends_line}</p></div></div>
</section>
"#,
    );

    // Page 4: timelines.
    let mut timelines = timeline(
        "Vault coins",
        "#1f5f8b",
        "Coins last moved",
        &[
            ("Any day".to_owned(), "Both keys".to_owned()),
            (
                format!("{} later", capitalize(&phone_wait)),
                "Phone alone".to_owned(),
            ),
            (
                format!("{} later", capitalize(&hww_wait)),
                "Hardware wallet alone".to_owned(),
            ),
        ],
    );
    for lock in &input.savings {
        let unlock = i64::from(lock.unlock);
        timelines.push_str(&timeline(
            &format!("Savings lock opening {}", date(unlock)),
            "#7a4f12",
            "Locked for everyone",
            &[
                (date(unlock), "Both keys".to_owned()),
                (
                    date(unlock + i64::from(SAVINGS_PHONE_RECOVERY_SECS)),
                    "Phone alone".to_owned(),
                ),
                (
                    date(unlock + i64::from(SAVINGS_HWW_RECOVERY_SECS)),
                    "Hardware wallet alone".to_owned(),
                ),
            ],
        ));
        if lock.uses_earlier_phone_key {
            timelines.push_str(r#"<div class="box warn"><p><strong>This savings lock uses an earlier phone key.</strong> The phone was replaced after this lock was created. Opening it with the phone needs that earlier phone's secret words. The hardware wallet works as usual.</p></div>"#);
        }
    }
    let _ = write!(
        html,
        r#"<section class="page">
<div class="label">3 · When each door opens</div>
<h2>Dates are enforced by Bitcoin, not by a company</h2>
<p>Read each line left to right. A door that is open stays open.</p>
{timelines}
<p class="note">Vault dates count from the last time the coins were moved, which normally happens once a year. Run <code>anzen coins</code> in the app to see the exact date for each coin today.</p>
</section>
"#,
    );

    // Page 5: steps.
    let _ = write!(
        html,
        r#"<section class="page">
<div class="label">4 · Step by step</div>
<h2>What to do, in order</h2>
<div class="box ok"><h3>Before anything else</h3><ol class="steps">
<li>Take your time. Nothing here expires quickly, and the bitcoin is safe while you read.</li>
<li>Never type the hardware wallet's secret words into a phone, computer or website. Nobody legitimate will ever ask for them.</li>
<li>Prepare a new wallet of your own to receive the bitcoin. A knowledgeable friend can help with this.</li>
</ol></div>
<div class="box"><h3>A · Both devices</h3><ol class="steps">
<li>Unlock the phone and open the Anzen app.</li>
<li>Choose <em>Move everything</em> and enter your new wallet's address.</li>
<li>Connect the hardware wallet, enter its PIN, and check that the address on its screen matches yours, character by character.</li>
<li>Approve on the hardware wallet. The app sends the coins.</li>
</ol><p class="note">Technical: <code>anzen phone create-sweep</code>, <code>anzen hww confirm-sweep</code>, <code>anzen phone broadcast-sweep</code>.</p></div>
<div class="box"><h3>B · Hardware wallet only</h3><ol class="steps">
<li>Install the Anzen app on a new phone and sign in to the owner's cloud account (Apple or Google).</li>
<li>Choose <em>Restore with hardware wallet</em>. Connect it and enter its PIN. It unlocks the backup and rebuilds the phone key.</li>
<li>Continue with situation A.</li>
</ol><p class="note">No cloud access? After {hww_wait} the hardware wallet alone can move vault coins: <code>anzen hww recover &lt;address&gt;</code>.</p></div>
<div class="box"><h3>C · Phone only</h3><ol class="steps">
<li>Keep the phone charged and safe. Do not reset it.</li>
<li>Open the app to see the date each coin opens for the phone alone.</li>
<li>On that date, choose <em>Recover with phone</em> and enter your new wallet's address.</li>
</ol><p class="note">Technical: <code>anzen phone recover &lt;address&gt;</code>.</p></div>
<div class="box"><h3>D · Recovery friend</h3><ol class="steps">
<li>Get a copy of the phone's encrypted cloud backup file from the family.</li>
<li>Use your personal recovery key to unlock it. The app shows the vault it belongs to.</li>
<li>After {phone_wait}, move the coins to the heir's new wallet.</li>
</ol><p class="note">Technical: <code>anzen social emergency-access &lt;backup&gt; --private-key &lt;your key&gt; &lt;address&gt;</code>.</p></div>
</section>
"#,
    );

    // Page 6: fill-in.
    let mut friend_rows = String::new();
    for friend in &input.friends {
        let _ = write!(
            friend_rows,
            "<div>Recovery friend</div><div>{}<br><span class=\"note\">Key fingerprint: <code>{}</code></span><br><span class=\"note\">Phone or email:</span></div>",
            esc(friend.name.as_deref().unwrap_or("(name not recorded)")),
            esc(&friend.fingerprint),
        );
    }
    let _ = write!(
        html,
        r#"<section class="page">
<div class="label">5 · Where things are kept</div>
<h2>Fill this in by hand, in pen</h2>
<p>Write <em>where</em> things are, never the codes themselves. For example: "PIN is in the sealed envelope in the safe deposit box", not the PIN.</p>
<div class="fill">
<div>Hardware wallet</div><div></div>
<div>Where its PIN is written</div><div></div>
<div>The phone</div><div></div>
<div>Where the phone's unlock code is written</div><div></div>
<div>Cloud account with the backup (Apple or Google)</div><div></div>
<div>Where the hardware wallet's secret words are</div><div></div>
{friend_rows}
<div>Lawyer or executor</div><div></div>
<div>Someone technical who can help</div><div></div>
</div>
</section>
"#,
    );

    // Page 7: technical.
    let mut savings_rows = String::new();
    for lock in &input.savings {
        let _ = write!(
            savings_rows,
            r#"<h3>Savings lock opening {}{}</h3><p class="label">Address</p><span class="mono">{}</span><p class="label">Descriptor</p><span class="mono">{}</span>"#,
            esc(&date(i64::from(lock.unlock))),
            if lock.default_deposit {
                " (default deposit address)"
            } else {
                ""
            },
            esc(&lock.address),
            esc(&lock.descriptor),
        );
    }
    let mut health = String::new();
    for (device, state) in &input.health {
        health.push_str(&health_line(*device, *state));
    }
    let _ = write!(
        html,
        r#"<section class="page">
<div class="label">6 · For a technical helper</div>
<h2>Exact details</h2>
<p>The vault is a standard Bitcoin Taproot output described by a Miniscript descriptor. Any wallet software that understands Miniscript descriptors can watch it, and can spend it given the matching keys. The Anzen app is a convenience, not a requirement. Delays are BIP68 relative timelocks in blocks (vault) and absolute timelocks (savings).</p>
<h3>Device health when printed</h3>
<ul>{health}</ul>
<h3>Vault</h3>
<p class="label">Address</p><span class="mono">{vault_address}</span>
<p class="label">Descriptor</p><span class="mono">{vault_descriptor}</span>
<p class="note">Phone alone: {phone_blocks} blocks after confirmation. Hardware wallet alone: {hww_blocks} blocks. Recovery friends unlock the phone's encrypted backup with their OpenPGP key and then use the phone path.</p>
{savings_rows}
</section>
"#,
        vault_address = esc(&input.vault_address),
        vault_descriptor = esc(&input.vault_descriptor),
        phone_blocks = input.phone_recovery_blocks,
        hww_blocks = input.hww_recovery_blocks,
    );

    // Page 8: glossary.
    html.push_str(r#"<section class="page">
<div class="label">7 · Words used in this kit</div>
<h2>Plain meanings</h2>
<div class="scroll"><table>
<tr><th>Word</th><th>What it means here</th></tr>
<tr><td>Key</td><td>A device that can approve moving the bitcoin. This vault has two: the phone and the hardware wallet.</td></tr>
<tr><td>Hardware wallet</td><td>A small single-purpose device that keeps a key offline. It shows what it is approving on its own screen.</td></tr>
<tr><td>PIN</td><td>The short code that unlocks the hardware wallet. Too many wrong tries erase it.</td></tr>
<tr><td>Secret words</td><td>A list of 12 or 24 words that can rebuild a key. Whoever has them has the key. Never type them anywhere.</td></tr>
<tr><td>Vault</td><td>Where most of the bitcoin is kept. Both keys open it at once; one key opens it after a wait.</td></tr>
<tr><td>Savings lock</td><td>Bitcoin that nobody can move before a set date, not even the owner.</td></tr>
<tr><td>Cloud backup</td><td>An encrypted copy of the phone key in the owner's Apple or Google account. It is useless without the hardware wallet or a recovery friend's key.</td></tr>
<tr><td>Recovery friend</td><td>A trusted person whose personal key can unlock the cloud backup. It still has to wait for the phone's delay.</td></tr>
<tr><td>Address</td><td>Where bitcoin is sent, like an account number. Always check it on the hardware wallet's screen.</td></tr>
</table></div>
</section>
</body></html>
"#);
    html
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> KitInput {
        KitInput {
            owner: Some("Ana <Silva>".to_owned()),
            generated_at: 1_792_108_800,
            network: Network::Regtest,
            vault_descriptor: "tr(abc,{multi_a(2,a,b)})".to_owned(),
            vault_address: "bcrt1pexample".to_owned(),
            phone_recovery_blocks: 61_200,
            hww_recovery_blocks: 65_535,
            monthly_limit_sats: 10_000_000,
            emergency_access_limit_sats: 0,
            savings: vec![KitSavings {
                unlock: 1_893_456_000,
                address: "bcrt1psave".to_owned(),
                descriptor: "tr(save)".to_owned(),
                default_deposit: true,
                uses_earlier_phone_key: true,
            }],
            friends: vec![KitFriend {
                name: Some("Alice".to_owned()),
                fingerprint: "6e32".to_owned(),
            }],
            health: vec![
                (Device::Phone, DeviceHealth::NeverChecked),
                (
                    Device::Hww,
                    DeviceHealth::Healthy {
                        checked_at: 1_792_000_000,
                        due_at: 1_800_000_000,
                    },
                ),
            ],
        }
    }

    #[test]
    fn kit_explains_every_route_in_plain_words() {
        let html = render(&input());
        for expected in [
            "How to get to Ana &lt;Silva&gt;&#39;s vault",
            "This kit cannot move money",
            "about 14 months",
            "about 15 months",
            "0.1 BTC",
            "Savings lock opening January 1, 2030",
            "March 2, 2031",
            "uses an earlier phone key",
            "Recovery friends set up: Alice.",
            "Not checked yet",
            "Test vault.",
            "bcrt1pexample",
        ] {
            assert!(html.contains(expected), "kit is missing {expected:?}");
        }
        assert!(!html.contains("<Silva>"), "owner name must be escaped");
    }

    #[test]
    fn kit_without_savings_or_friends_says_so() {
        let mut input = input();
        input.savings.clear();
        input.friends.clear();
        input.network = Network::Bitcoin;
        let html = render(&input);
        assert!(html.contains("No recovery friends were set up"));
        assert!(!html.contains("Savings lock opening"));
        assert!(!html.contains("Test vault."));
    }

    #[test]
    fn btc_amounts_trim_trailing_zeros() {
        assert_eq!(btc(100_000_000), "1 BTC");
        assert_eq!(btc(50_000_000), "0.5 BTC");
        assert_eq!(btc(1), "0.00000001 BTC");
    }
}
