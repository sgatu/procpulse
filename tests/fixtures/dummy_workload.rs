use std::thread::sleep;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    println!("Dummy workload started with args: {:?}", args);

    // Run for 8 seconds, periodically doing light CPU work
    let start = std::time::Instant::now();
    let mut counter: u64 = 0;
    while start.elapsed() < Duration::from_secs(8) {
        for i in 0..50_000 {
            counter = counter.wrapping_add(i);
        }
        sleep(Duration::from_millis(100));
    }

    println!("Dummy workload exiting (counter: {})", counter);
}
