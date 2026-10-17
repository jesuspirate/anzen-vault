//! The printable recovery kit.
//!
//! One self-contained HTML document, laid out as printed pages, that explains the vault to the
//! people who will need it most and know it least: an heir, a recovery friend, or the owner years
//! from now. It is written in plain language with pictures first and technical detail last.
//!
//! The kit contains public information only (descriptors, addresses, dates, friend fingerprints,
//! the heir's public key).
//! It cannot move coins. It does reveal where the coins are, so it is private.

use super::{
    health::{Device, DeviceHealth},
    policy::{SAVINGS_HEIR_RECOVERY_SECS, SAVINGS_HWW_RECOVERY_SECS, SAVINGS_PHONE_RECOVERY_SECS},
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
    /// The lock was created with the named heir's key in it.
    pub heir: bool,
}

#[derive(Debug, Clone)]
pub struct KitHeir {
    pub name: String,
    pub key: String,
    pub recovery_blocks: u16,
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
    pub heir: Option<KitHeir>,
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
.box{border:2px solid var(--line);border-radius:10px;padding:16px;display:grid;gap:8px;align-content:start;break-inside:avoid}
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
const HEIR_ICON: &str = r##"<g><circle cx="0" cy="-12" r="11" fill="#ffffff" stroke="#1b2430" stroke-width="3"/><path d="M-20 24 C-20 6 20 6 20 24 Z" fill="#ffffff" stroke="#1b2430" stroke-width="3"/><circle cx="20" cy="-14" r="6" fill="#256b3e"/><rect x="18" y="-9" width="4" height="14" fill="#256b3e"/></g>"##;
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

/// A horizontal timeline from a start point through the dates each door opens. Labels alternate
/// between two rows so that neighbouring dates never overlap.
fn timeline(title: &str, color: &str, start: &str, stops: &[(String, String)]) -> String {
    let width = 720;
    let left = 40;
    let right = width - 40;
    let mut svg = format!(
        r##"<svg viewBox="0 0 {width} 180" role="img" aria-label="{}">
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
        let (label_x, top) = match anchor {
            "end" => (x + 11, 96),
            _ => (x, 96),
        };
        let top = if index % 2 == 1 { top + 50 } else { top };
        if index % 2 == 1 {
            let _ = write!(
                svg,
                r##"<line x1="{x}" y1="72" x2="{x}" y2="{}" stroke="{color}" stroke-width="2" stroke-dasharray="3 3"/>"##,
                top - 18
            );
        }
        let _ = write!(
            svg,
            r##"<circle cx="{x}" cy="60" r="11" fill="#ffffff" stroke="{color}" stroke-width="5"/>
<text x="{label_x}" y="{top}" text-anchor="{anchor}" font-size="14" font-weight="700" fill="#1b2430">{}</text>
<text x="{label_x}" y="{}" text-anchor="{anchor}" font-size="13" fill="#4f5b6b">{}</text>
"##,
            esc(when),
            top + 22,
            esc(what),
        );
    }
    svg.push_str("</svg>");
    svg
}

/// The heir's clock: while the owner is active the vault coins keep moving and the clock keeps
/// starting over; once they stop, the long wait runs out and the heir's own key opens.
fn heir_clock(name: &str, wait: &str) -> String {
    let mut svg = format!(
        r##"<svg viewBox="0 0 720 210" role="img" aria-label="While the owner is active the clock restarts every year; after the last move, {name_attr}'s key opens after {wait_attr}">
<defs><marker id="heir-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerUnits="userSpaceOnUse" markerWidth="16" markerHeight="16" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#256b3e"/></marker>
<marker id="restart" viewBox="0 0 10 10" refX="5" refY="5" markerUnits="userSpaceOnUse" markerWidth="9" markerHeight="9" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#1f5f8b"/></marker></defs>
<text x="40" y="24" font-size="14" font-weight="700" fill="#1b2430">While the owner is active</text>
<text x="40" y="43" font-size="13" fill="#4f5b6b">Each yearly move sets the clock back to zero</text>
<line x1="40" y1="110" x2="300" y2="110" stroke="#1f5f8b" stroke-width="6" stroke-linecap="round"/>
"##,
        name_attr = esc(name),
        wait_attr = esc(wait),
    );
    for x in [60, 160, 260] {
        let _ = write!(
            svg,
            r##"<circle cx="{x}" cy="110" r="11" fill="#1f5f8b"/><path d="M{a} 88 A 13 13 0 1 1 {b} 88" fill="none" stroke="#1f5f8b" stroke-width="3" marker-end="url(#restart)"/><text x="{x}" y="146" text-anchor="middle" font-size="13" fill="#4f5b6b">moved</text>"##,
            a = x - 8,
            b = x + 8,
        );
    }
    let _ = write!(
        svg,
        r##"<text x="330" y="24" font-size="14" font-weight="700" fill="#1b2430">After the owner stops</text>
<text x="330" y="43" font-size="13" fill="#4f5b6b">Nothing moves the coins, so the clock keeps running</text>
<circle cx="340" cy="110" r="11" fill="#ffffff" stroke="#1f5f8b" stroke-width="5"/>
<text x="340" y="146" text-anchor="middle" font-size="13" fill="#4f5b6b">last move</text>
<line x1="356" y1="110" x2="606" y2="110" stroke="#256b3e" stroke-width="6" stroke-dasharray="10 8" marker-end="url(#heir-arrow)"/>
<text x="478" y="92" text-anchor="middle" font-size="14" font-weight="700" fill="#256b3e">{wait} of silence</text>
<g transform="translate(650,106)">{HEIR_ICON}</g>
<text x="680" y="152" text-anchor="end" font-size="14" font-weight="700" fill="#1b2430">{name}'s own key opens</text>
<text x="680" y="171" text-anchor="end" font-size="13" fill="#4f5b6b">no phone or hardware wallet needed</text>
<text x="40" y="200" font-size="13" fill="#4f5b6b">The dates are kept by the Bitcoin network. No company, and not even {name}, can change them.</text>
</svg>"##,
        wait = esc(&capitalize(wait)),
        name = esc(name),
    );
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
    let heir = input.heir.as_ref().map(|heir| {
        let name = heir.name.trim();
        let wait = months_label(blocks_to_days(heir.recovery_blocks));
        (if name.is_empty() { "the heir" } else { name }, wait, heir)
    });
    let network_note = match input.network {
        Network::Bitcoin => String::new(),
        _ => r#"<div class="box warn"><strong>Test vault.</strong> This kit describes a vault on a Bitcoin test network. It holds no real bitcoin.</div>"#.to_owned(),
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
<li>Which situation are you in?{heir_toc}</li>
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
        heir_toc = heir.as_ref().map_or_else(String::new, |(name, ..)| format!(
            " (including {}, the named heir)",
            esc(name)
        )),
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
    if let Some((name, wait, _)) = &heir {
        let _ = write!(
            money,
            "<li><strong>{name} is the named heir</strong> and has a key of their own. It cannot touch the vault while {person} is using it. It opens only after the vault coins have not moved for {wait}. The next section shows how that works.</li>",
            name = esc(name),
            person = owner.map_or_else(|| "the owner".to_owned(), esc),
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

    // Page 2b: the heir's door.
    if let Some((name, wait, _)) = &heir {
        let person = owner.map_or_else(|| "the owner".to_owned(), esc);
        let _ = write!(
            html,
            r#"<section class="page">
<div class="label">1 · The big picture, continued</div>
<h2>{name}'s own door</h2>
<p class="big">{name} holds a third key that belongs to {name} alone. It is a quiet door: it stays shut while {person} uses the vault, and opens by itself when {person} stops.</p>
{clock}
<div class="grid">
<div class="box ok"><h3>How the door knows</h3><p>Every year {person}'s app moves the vault coins as part of its normal routine. Each move sets the clock back to zero. When nobody moves the coins any more, the clock keeps running, and after {wait} {name}'s key works.</p></div>
<div class="box"><h3>What {name} needs</h3><p>Only {name}'s own key (a hardware wallet or the secret words that {name} keeps) and this kit. Not {person}'s phone, not the hardware wallet, not any password.</p></div>
<div class="box warn"><h3>Why it waits so long</h3><p>{wait_title} is the longest wait Bitcoin allows. It makes sure {name}'s key works only after a long silence, never while {person} is using the vault.</p></div>
</div>
<p class="note">If {person}'s phone is still switched on, it may make one more prepared yearly move by itself, which can push the date back by up to a year. Savings locks have their own fixed heir date, shown in section 3.</p>
</section>
"#,
            name = esc(name),
            clock = heir_clock(name, wait),
            wait_title = capitalize(wait),
        );
    }

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
{heir_situation}</section>
"#,
        heir_situation = heir.as_ref().map_or_else(String::new, |(name, wait, _)| format!(
            r#"<div class="box situation ok"><div class="letter">E</div><div><h3>You are {name}, the named heir</h3><p>Your own key opens the vault once its coins have not moved for {wait}. You need nothing else from the owner. If you also have the owner's devices, situation A is faster.</p></div></div>
"#,
            name = esc(name),
        )),
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
                match &heir {
                    Some((name, ..)) => format!("Hardware wallet alone, or {name}"),
                    None => "Hardware wallet alone".to_owned(),
                },
            ),
        ],
    );
    for lock in &input.savings {
        let unlock = i64::from(lock.unlock);
        let mut stops = vec![
            (date(unlock), "Both keys".to_owned()),
            (
                date(unlock + i64::from(SAVINGS_PHONE_RECOVERY_SECS)),
                "Phone alone".to_owned(),
            ),
            (
                date(unlock + i64::from(SAVINGS_HWW_RECOVERY_SECS)),
                "Hardware wallet alone".to_owned(),
            ),
        ];
        if let (true, Some((name, ..))) = (lock.heir, &heir) {
            stops.push((
                date(unlock + i64::from(SAVINGS_HEIR_RECOVERY_SECS)),
                format!("{name}'s own key"),
            ));
        }
        timelines.push_str(&timeline(
            &format!("Savings lock opening {}", date(unlock)),
            "#7a4f12",
            "Locked for everyone",
            &stops,
        ));
        if let (false, Some((name, ..))) = (lock.heir, &heir) {
            let _ = write!(
                timelines,
                r#"<div class="box warn"><p><strong>{} has no key to this savings lock.</strong> It was created before {} was named as heir, so only the phone and the hardware wallet can open it.</p></div>"#,
                esc(&capitalize(name)),
                esc(name),
            );
        }
        if lock.uses_earlier_phone_key {
            let _ = write!(
                timelines,
                r#"<div class="box warn"><p><strong>This savings lock was made with an earlier phone key.</strong> The phone was replaced after this lock was created. The current phone keeps a copy of the earlier key, so do not reset or replace it. If that phone is gone, the hardware wallet alone can still open this lock from {}.</p></div>"#,
                esc(&date(unlock + i64::from(SAVINGS_HWW_RECOVERY_SECS)))
            );
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
<li>If you are unsure which situation you are in, ask a technical helper to look at section 6. It only needs this kit.</li>
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
{heir_steps}</section>
"#,
        heir_steps = heir.as_ref().map_or_else(String::new, |(name, wait, _)| format!(
            r#"<div class="box ok"><h3>E · {name}, the named heir</h3><ol class="steps">
<li>Find your own key: your hardware wallet, or the secret words you were given. Only ever enter those words into your own hardware wallet or the Anzen app on your own device, never into a website or someone else's device.</li>
<li>Open the Anzen app with your key and this kit. It shows the day your key opens: {wait} after the vault coins last moved, and a fixed date for each savings lock.</li>
<li>Before that day, nothing can be done and nothing is lost. Put a reminder in your calendar.</li>
<li>On that day, choose <em>Claim as heir</em> and enter the address of your own new wallet. Check it character by character.</li>
<li>The app moves every coin your key can open. Coins in a savings lock that opens later can be claimed on their own date.</li>
</ol><p class="note">Technical, on {name}'s own computer: <code>anzen heir restore --vault-descriptor &lt;vault descriptor&gt; --savings-descriptor &lt;each savings descriptor&gt;</code> using the descriptors in section 6, then <code>anzen heir status</code> for the dates and <code>anzen heir claim &lt;address&gt;</code> to move the coins.</p></div>
"#,
            name = esc(name),
        )),
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
    let heir_rows = heir.as_ref().map_or_else(String::new, |(name, ..)| format!(
        "<div>{} (the heir)</div><div><span class=\"note\">Phone or email:</span><br><span class=\"note\">Where {} keeps their own key:</span></div>",
        esc(&capitalize(name)),
        esc(name),
    ));
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
{heir_rows}{friend_rows}
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
{heir_details}{savings_rows}
</section>
"#,
        vault_address = esc(&input.vault_address),
        vault_descriptor = esc(&input.vault_descriptor),
        phone_blocks = input.phone_recovery_blocks,
        hww_blocks = input.hww_recovery_blocks,
        heir_details = heir.as_ref().map_or_else(String::new, |(name, _, heir)| format!(
            r#"<h3>Heir</h3><p class="label">{}'s key</p><span class="mono">{}</span><p class="note">The heir leaf is <code>and_v(v:older({}),pk(heir))</code> in the vault and <code>and_v(v:pk(heir),after(unlock + {} days))</code> in each savings lock that names the heir. The heir signs alone with the key at <code>/2/0</code> below the account key shown.</p>"#,
            esc(&capitalize(name)),
            esc(&heir.key),
            heir.recovery_blocks,
            SAVINGS_HEIR_RECOVERY_SECS / 86_400,
        )),
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
<tr><td>Heir key</td><td>A key that belongs to the person named as heir. It opens the vault only after the coins have not moved for a long time.</td></tr>
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
                heir: true,
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
            heir: None,
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
            "made with an earlier phone key",
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
    fn kit_explains_the_heir_door_when_an_heir_is_named() {
        let mut input = input();
        assert!(!render(&input).contains("named heir"));
        input.heir = Some(KitHeir {
            name: "Bea <B>".to_owned(),
            key: "[abcd1234/86'/1'/100'/0/0]tpubheir".to_owned(),
            recovery_blocks: 65_535,
        });
        input.savings.push(KitSavings {
            unlock: 1_924_992_000,
            address: "bcrt1pold".to_owned(),
            descriptor: "tr(old)".to_owned(),
            default_deposit: false,
            uses_earlier_phone_key: false,
            heir: false,
        });
        let html = render(&input);
        for expected in [
            "Bea &lt;B&gt;'s own door",
            "You are Bea &lt;B&gt;, the named heir",
            "E · Bea &lt;B&gt;, the named heir",
            "Hardware wallet alone, or Bea &lt;B&gt;",
            // 2030-01-01 plus 485 days.
            "May 1, 2031",
            "has no key to this savings lock",
            "[abcd1234/86&#39;/1&#39;/100&#39;/0/0]tpubheir",
            "anzen heir claim",
            "of silence",
        ] {
            assert!(html.contains(expected), "kit is missing {expected:?}");
        }
        assert!(!html.contains("<B>"), "heir name must be escaped");
    }

    #[test]
    fn btc_amounts_trim_trailing_zeros() {
        assert_eq!(btc(100_000_000), "1 BTC");
        assert_eq!(btc(50_000_000), "0.5 BTC");
        assert_eq!(btc(1), "0.00000001 BTC");
    }
}
