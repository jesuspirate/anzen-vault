//! BIP388 wallet policies: the form in which stock hardware wallets register Anzen's policies.

use anyhow::{Result, ensure};
use miniscript::{Descriptor, DescriptorPublicKey, ForEachKey};

/// Split a multipath descriptor into a BIP388 template and its key list: each distinct key
/// becomes `@i`, and `/<0;1>/*` becomes `/**`.
pub fn template(descriptor: &Descriptor<DescriptorPublicKey>) -> Result<(String, Vec<String>)> {
    let text = descriptor.to_string();
    let mut template = text.split('#').next().unwrap_or_default().to_owned();
    let mut keys: Vec<String> = Vec::new();
    descriptor.for_each_key(|key| {
        let text = key.to_string();
        let base = text
            .split_once("/<")
            .map(|(base, _)| base.to_owned())
            .unwrap_or(text);
        if !keys.contains(&base) {
            keys.push(base);
        }
        true
    });
    // Replace longer keys first so a key that is a prefix of another cannot clash.
    let mut order: Vec<usize> = (0..keys.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(keys[i].len()));
    for i in order {
        template = template.replace(&keys[i], &format!("@{i}"));
    }
    template = template.replace("/<0;1>/*", "/**");
    ensure!(
        !template.contains("pub"),
        "could not turn the descriptor into a wallet policy template"
    );
    Ok((template, keys))
}
