//! Prints the detected cgroup memory limit and the auto budget.
//! Used to verify container-limit clamping: run inside
//! `docker run --memory 1g` and expect limit ≈ 1 GiB, budget = half.

fn main() {
    let gb = |b: u64| b as f64 / (1u64 << 30) as f64;
    println!(
        "physical_ram: {:?} GB",
        nzbkit::mem::physical_ram().map(gb)
    );
    println!(
        "cgroup_mem_limit: {:?} GB",
        nzbkit::mem::cgroup_mem_limit().map(gb)
    );
    println!("auto budget: {:.2} GB", gb(nzbkit::mem::MemBudget::auto().total));
}
