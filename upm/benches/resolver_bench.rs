use criterion::{criterion_group, criterion_main, Criterion};
use upm_resolver_rs::{resolve_deps, build_graph};  // Import your lib functions

fn bench_resolve_deps(c: &mut Criterion) {
    let manifest = r#"{"dependencies": {"python": [{"name": "numpy", "version": ">=1.0.0", "ecosystem": "python"}]}}"#;
    let policies = r#"{"blocked_packages": []}"#;
    c.bench_function("resolve_deps", |b| b.iter(|| resolve_deps(manifest.to_string(), policies.to_string())));
}

fn bench_build_graph(c: &mut Criterion) {
    let manifest = r#"{"dependencies": {"npm": [{"name": "express", "version": "^4.0.0", "ecosystem": "npm"}]}}"#;
    let policies = r#"{"pinned_versions": {}}"#;
    c.bench_function("build_graph", |b| b.iter(|| build_graph(manifest.to_string(), policies.to_string())));
}

criterion_group!(benches, bench_resolve_deps, bench_build_graph);
criterion_main!(benches);