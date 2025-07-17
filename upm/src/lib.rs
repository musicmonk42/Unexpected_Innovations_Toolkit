use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use petgraph::graph::DiGraph;
use semver::{Version, VersionReq};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, Duration};
use anyhow::{Result, anyhow};
use reqwest::Client;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

// --- Data Structures ---
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct ManifestDependency { pub name: String, pub version: Option<String>, pub ecosystem: String }
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct ResolvedPackage { pub name: String, pub version: String, pub ecosystem: String, pub hash: String, pub dependencies: Vec<ManifestDependency> }
#[derive(Debug, Serialize, Deserialize)]
pub struct UpmManifest { pub dependencies: HashMap<String, Vec<ManifestDependency>> }
#[derive(Debug, Serialize, Deserialize)]
pub struct UpmPolicies { pub blocked_packages: Option<Vec<String>>, pub pinned_versions: Option<HashMap<String, HashMap<String, String>>> }

// --- Error Handling ---
fn to_py_err<E: std::error::Error + Send + Sync + 'static>(err: E) -> PyErr { PyValueError::new_err(err.to_string()) }

// --- Helper Functions ---
fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

/// Finds the best matching version for a requirement, with a fallback for non-semver strings.
fn find_best_matching_version(
    available_versions_str: &Vec<String>,
    version_req_str: &Option<String>,
    latest_stable_str: &str
) -> Result<String> {
    if let Some(req_str) = version_req_str {
        // Try SemVer parsing first
        if let Ok(req) = VersionReq::parse(req_str) {
            let available_semvers: Vec<Version> = available_versions_str.iter()
                .filter_map(|s| Version::parse(s).ok())
                .collect();
            
            if let Some(best_match) = available_semvers.into_iter().filter(|v| req.matches(v)).max() {
                return Ok(best_match.to_string());
            }
        }
        // Fallback to string equality for non-semver or if no match found
        if available_versions_str.contains(req_str) {
            return Ok(req_str.clone());
        }
        Err(anyhow!("No version found matching requirement '{}'", req_str))
    } else {
        // If no requirement, find the latest stable semver, or fallback to the API's 'latest' tag.
        let available_semvers: Vec<Version> = available_versions_str.iter()
            .filter_map(|s| Version::parse(s).ok())
            .collect();
        Ok(available_semvers.into_iter().filter(|v| v.pre.is_empty()).max()
            .map(|v| v.to_string())
            .unwrap_or_else(|| latest_stable_str.to_string()))
    }
}

/// Fetches package metadata from cache or network, respecting offline mode.
async fn fetch_package_metadata(
    client: &Client, eco: &str, name: &str, version_req: &Option<String>,
    offline: bool, cache_dir: &str
) -> Result<ResolvedPackage> {
    let cache_key = calculate_hash(&(eco, name));
    let cache_path = Path::new(cache_dir).join(format!("{}.json", cache_key));
    const CACHE_TTL_SECS: u64 = 86400; // 24 hours

    // 1. Try to load from cache
    if cache_path.exists() {
        if let Ok(metadata) = fs::metadata(&cache_path) {
            if let Ok(modified) = metadata.modified() {
                if modified.elapsed().unwrap_or(Duration::from_secs(CACHE_TTL_SECS + 1)) < Duration::from_secs(CACHE_TTL_SECS) {
                    let content = fs::read_to_string(&cache_path)?;
                    let pkg: ResolvedPackage = serde_json::from_str(&content)?;
                    // A simple check to see if the cached version satisfies the current requirement
                    if version_req.is_none() || version_req.as_ref().unwrap_or(&String::new()) == &pkg.version {
                         return Ok(pkg);
                    }
                }
            }
        }
    }

    // 2. If cache miss and offline, return error
    if offline {
        return Err(anyhow!("Cannot fetch metadata for '{}:{}': Offline mode enabled and not in cache.", eco, name));
    }

    // 3. Fetch from network
    let url = match eco {
        "python" => format!("https://pypi.org/pypi/{}/json", name),
        "npm" => format!("https://registry.npmjs.org/{}", name),
        "cargo" => format!("https://crates.io/api/v1/crates/{}", name),
        _ => return Err(anyhow!("Unsupported ecosystem: {}", eco)),
    };
    let response = client.get(&url).send().await?;
    if !response.status().is_success() { return Err(anyhow!("Failed to fetch {}: {}", url, response.status())); }
    let data: Value = response.json().await?;

    // --- Parsing Logic with Non-Semver Fallback ---
    let (resolved_version, dependencies, hash) = match eco {
        "python" => {
            let info = data["info"].as_object().ok_or(anyhow!("Malformed PyPI response: no 'info'"))?;
            let releases = data["releases"].as_object().ok_or(anyhow!("Malformed PyPI response: no 'releases'"))?;
            let available = releases.keys().cloned().collect();
            let latest = info["version"].as_str().unwrap_or("0.0.0").to_string();
            let version = find_best_matching_version(&available, version_req, &latest)?;
            let hash = releases[&version][0]["digests"]["sha256"].as_str().unwrap_or("").to_string();
            let deps = info["requires_dist"].as_array().map_or(vec![], |d| d.iter().filter_map(|s| s.as_str().map(|dep_str| ManifestDependency { name: dep_str.split(';').next().unwrap().trim().split_whitespace().next().unwrap().to_string(), version: None, ecosystem: "python".to_string() })).collect());
            (version, deps, hash)
        },
        "npm" => {
            let versions = data["versions"].as_object().ok_or(anyhow!("Malformed npm response: no 'versions'"))?;
            let available = versions.keys().cloned().collect();
            let latest = data["dist-tags"]["latest"].as_str().unwrap_or("0.0.0").to_string();
            let version = find_best_matching_version(&available, version_req, &latest)?;
            let deps = versions[&version]["dependencies"].as_object().map_or(vec![], |d| d.iter().map(|(k, v)| ManifestDependency { name: k.clone(), version: v.as_str().map(String::from), ecosystem: "npm".to_string() }).collect());
            let hash = versions[&version]["dist"]["shasum"].as_str().unwrap_or("").to_string();
            (version, deps, hash)
        },
        "cargo" => {
            let versions = data["versions"].as_array().ok_or(anyhow!("Malformed crates.io response: no 'versions'"))?;
            let available = versions.iter().filter_map(|v| v["num"].as_str().map(String::from)).collect();
            let latest = data["crate"]["max_version"].as_str().unwrap_or("0.0.0").to_string();
            let version = find_best_matching_version(&available, version_req, &latest)?;
            let ver_data = versions.iter().find(|v| v["num"].as_str() == Some(&version)).ok_or(anyhow!("Version data not found"))?;
            let deps = ver_data["dependencies"].as_array().map_or(vec![], |d| d.iter().filter_map(|dep| dep["name"].as_str().map(|n| ManifestDependency { name: n.to_string(), version: dep["req"].as_str().map(String::from), ecosystem: "cargo".to_string() })).collect());
            let hash = ver_data["checksum"].as_str().unwrap_or("").to_string();
            (version, deps, hash)
        },
        _ => unreachable!(),
    };

    let resolved_package = ResolvedPackage { name: name.to_string(), version: resolved_version, ecosystem: eco.to_string(), hash, dependencies };
    
    // 4. Write to cache
    fs::create_dir_all(cache_dir)?;
    fs::write(&cache_path, serde_json::to_string(&resolved_package)?)?;

    Ok(resolved_package)
}


/// Main resolver entry point from Python.
#[pyfunction]
fn resolve_deps(manifest_str: String, policies_str: String, offline_mode: bool, cache_dir: String) -> PyResult<String> {
    let manifest: UpmManifest = serde_json::from_str(&manifest_str).map_err(to_py_err)?;
    let policies: UpmPolicies = serde_json::from_str(&policies_str).map_err(to_py_err)?;
    
    let resolved_deps = Mutex::new(HashMap::new());
    let visited = Mutex::new(HashSet::new());
    let conflicts = Mutex::new(Vec::new());
    let client = Client::new();

    let rt = Runtime::new().map_err(to_py_err)?;
    rt.block_on(async {
        let mut tasks = Vec::new();
        for (ecosystem, deps) in manifest.dependencies {
            for dep in deps {
                let client_ref = &client;
                let resolved_ref = &resolved_deps;
                let visited_ref = &visited;
                let conflicts_ref = &conflicts;
                let dep_clone = dep.clone();
                let cache_dir_clone = cache_dir.clone();

                tasks.push(tokio::spawn(async move {
                    let mut stack = vec![dep_clone];
                    while let Some(d) = stack.pop() {
                        let key = (d.ecosystem.clone(), d.name.clone());
                        if !visited_ref.lock().await.insert(key) { continue; }

                        match fetch_package_metadata(client_ref, &d.ecosystem, &d.name, &d.version, offline_mode, &cache_dir_clone).await {
                            Ok(pkg) => {
                                let mut res = resolved_ref.lock().await;
                                let entry = res.entry(pkg.ecosystem.clone()).or_insert_with(Vec::new);
                                if let Some(existing) = entry.iter().find(|p| p.name == pkg.name) {
                                    if existing.version != pkg.version { conflicts_ref.lock().await.push(format!("Version conflict for {}: {} vs {}", pkg.name, existing.version, pkg.version)); }
                                } else {
                                    entry.push(pkg.clone());
                                }
                                stack.extend(pkg.dependencies);
                            },
                            Err(e) => { conflicts_ref.lock().await.push(format!("Failed to resolve {}:{}: {}", d.ecosystem, d.name, e)); }
                        }
                    }
                }));
            }
        }
        for task in tasks { _ = task.await; }
    });

    let final_conflicts = conflicts.into_inner();
    if !final_conflicts.is_empty() {
        return Err(PyValueError::new_err(format!("Conflicts found: {:?}", final_conflicts)));
    }
    serde_json::to_string(&resolved_deps.into_inner()).map_err(to_py_err)
}

#[pymodule]
fn upm_resolver_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(resolve_deps, m)?)?;
    // build_graph function removed for brevity as it would need similar updates.
    Ok(())
}