//! Which scripts `CREATE EXTENSION ... VERSION v` runs (RT4-6, F1 audit).
//!
//! PostgreSQL runs every script of an extension under the control file of the
//! version that script installs, so `/extensions` may run a `CREATE` only when
//! each version whose script it runs is trusted. Without an install script of
//! its own (`<ext>--<v>.sql`), `CREATE ... VERSION v` runs another version's
//! install script and then an update path to `v`: this module computes that
//! chain from the extension's script file names, as PostgreSQL 17's
//! `find_install_path` and `find_update_path` (`reject_indirect`) do.

use std::collections::{BTreeMap, BTreeSet};

/// The versions and update edges an extension's script files define.
#[derive(Debug, Default)]
pub struct ScriptGraph {
    /// Versions with an install script of their own (`<ext>--<v>.sql`).
    installable: BTreeSet<String>,
    /// `<ext>--<a>--<b>.sql`: `a` → its `b`s.
    edges: BTreeMap<String, BTreeSet<String>>,
}

impl ScriptGraph {
    /// The graph of extension `ext` from the file names of its script
    /// directory (names of other extensions and other files are ignored, as is
    /// a name with more than one `--` after the extension's, as PostgreSQL does).
    pub fn from_file_names<'a>(ext: &str, names: impl IntoIterator<Item = &'a str>) -> Self {
        let prefix = format!("{ext}--");
        let mut graph = ScriptGraph::default();
        for name in names {
            let Some(rest) = name
                .strip_prefix(&prefix)
                .and_then(|r| r.strip_suffix(".sql"))
            else {
                continue;
            };
            match rest.split_once("--") {
                None if !rest.is_empty() => {
                    graph.installable.insert(rest.to_owned());
                }
                None => {}
                Some((from, to)) => {
                    if from.is_empty() || to.is_empty() || to.contains("--") {
                        continue;
                    }
                    graph
                        .edges
                        .entry(from.to_owned())
                        .or_default()
                        .insert(to.to_owned());
                }
            }
        }
        graph
    }

    /// The update path from `start` to `target` (the versions after `start`,
    /// `target` last), as `find_update_path`: shortest, ties to the
    /// predecessor with the greatest name; with `reject_indirect`, never
    /// through another installable version. `None` without a path.
    fn update_path(&self, start: &str, target: &str, reject_indirect: bool) -> Option<Vec<String>> {
        if start == target {
            return None;
        }
        let mut previous: BTreeMap<&str, &str> = BTreeMap::new();
        let mut known: BTreeSet<&str> = BTreeSet::from([start]);
        let mut layer: Vec<&str> = vec![start];
        while !layer.is_empty() && !previous.contains_key(target) {
            let mut next: BTreeMap<&str, &str> = BTreeMap::new();
            for &from in &layer {
                for to in self.edges.get(from).into_iter().flatten() {
                    let to = to.as_str();
                    if known.contains(to)
                        || (reject_indirect && to != target && self.installable.contains(to))
                    {
                        continue;
                    }
                    // Ties go to the predecessor with the greatest name.
                    let entry = next.entry(to).or_insert(from);
                    if *entry < from {
                        *entry = from;
                    }
                }
            }
            layer = next.keys().copied().collect();
            for (&to, &from) in &next {
                known.insert(to);
                previous.insert(to, from);
            }
        }
        previous.get(target)?;
        let mut path = vec![target.to_owned()];
        let mut at = target;
        while let Some(&from) = previous.get(at) {
            if from == start {
                break;
            }
            path.push(from.to_owned());
            at = from;
        }
        path.reverse();
        Some(path)
    }

    /// Every version whose script `CREATE EXTENSION ... VERSION target` runs,
    /// in order: `[target]` when it has an install script; else the
    /// installable start with the shortest path not through another
    /// installable version (ties to the greatest start name), then that path.
    /// `None` when PostgreSQL can't install `target`.
    pub fn create_chain(&self, target: &str) -> Option<Vec<String>> {
        if self.installable.contains(target) {
            return Some(vec![target.to_owned()]);
        }
        let mut best: Option<(&str, Vec<String>)> = None;
        for start in &self.installable {
            let Some(path) = self.update_path(start, target, true) else {
                continue;
            };
            let better = match &best {
                None => true,
                Some((best_start, best_path)) => {
                    path.len() < best_path.len()
                        || (path.len() == best_path.len() && best_start < &start.as_str())
                }
            };
            if better {
                best = Some((start, path));
            }
        }
        best.map(|(start, path)| {
            let mut chain = vec![start.to_owned()];
            chain.extend(path);
            chain
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ScriptGraph;

    fn graph(ext: &str, names: &[&str]) -> ScriptGraph {
        ScriptGraph::from_file_names(ext, names.iter().copied())
    }

    fn chain(g: &ScriptGraph, target: &str) -> Option<Vec<String>> {
        g.create_chain(target)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn some(versions: &[&str]) -> Option<Vec<String>> {
        Some(versions.iter().map(|v| v.to_string()).collect())
    }

    #[test]
    fn the_fixture_extensions() {
        let up = graph(
            "f1_update_path",
            &[
                "f1_update_path--1.0.sql",
                "f1_update_path--1.0--1.1.sql",
                "f1_update_path--1.1--1.2.sql",
                "f1_update_path--1.0--1.3.sql",
                "f1_update_path.control",
                "f1_update_path--1.1.control",
            ],
        );
        assert_eq!(chain(&up, "1.0"), some(&["1.0"]));
        assert_eq!(chain(&up, "1.2"), some(&["1.0", "1.1", "1.2"]));
        assert_eq!(chain(&up, "1.3"), some(&["1.0", "1.3"]));
        assert_eq!(chain(&up, "9.9"), None);

        let ip = graph(
            "f1_install_path",
            &[
                "f1_install_path--1.0.sql",
                "f1_install_path--1.0--1.1.sql",
                "f1_install_path--1.1--2.0.sql",
                "f1_install_path--2.0.sql",
                "f1_install_path--2.0--2.1.sql",
            ],
        );
        assert_eq!(chain(&ip, "1.1"), some(&["1.0", "1.1"]));
        assert_eq!(chain(&ip, "2.0"), some(&["2.0"]));
        // 1.0 -> 1.1 -> 2.0 -> 2.1 passes through the installable 2.0: rejected.
        assert_eq!(chain(&ip, "2.1"), some(&["2.0", "2.1"]));
    }

    #[test]
    fn ties_and_rejected_paths() {
        // Two starts at the same distance: the greater name wins.
        let g = graph("e", &["e--a.sql", "e--b.sql", "e--a--x.sql", "e--b--x.sql"]);
        assert_eq!(chain(&g, "x"), some(&["b", "x"]));
        // Two predecessors at the same distance: the greater name wins.
        let g = graph(
            "e",
            &[
                "e--s.sql",
                "e--s--p.sql",
                "e--s--q.sql",
                "e--p--t.sql",
                "e--q--t.sql",
            ],
        );
        assert_eq!(chain(&g, "t"), some(&["s", "q", "t"]));
        // The only path runs through another installable version: none.
        let g = graph("e", &["e--a.sql", "e--b.sql", "e--a--b.sql", "e--b--c.sql"]);
        assert_eq!(chain(&g, "c"), some(&["b", "c"]));
        let g = graph("e", &["e--a.sql", "e--m.sql", "e--a--m.sql", "e--m--z.sql"]);
        assert_eq!(g.update_path("a", "z", true), None);
        // Other extensions' files, a prefix match and odd names are ignored.
        let g = graph(
            "e",
            &[
                "ee--1.sql",
                "e--.sql",
                "e----1.sql",
                "e--1--2--3.sql",
                "e--1.sql",
            ],
        );
        assert_eq!(chain(&g, "1"), some(&["1"]));
        assert_eq!(chain(&g, "3"), None);
        // A cycle doesn't loop.
        let g = graph("e", &["e--1.sql", "e--1--2.sql", "e--2--1.sql"]);
        assert_eq!(chain(&g, "2"), some(&["1", "2"]));
    }
}
