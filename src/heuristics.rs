/*
 * Oversight - Heuristic Analysis Engine
 * Logic for detecting high-entropy blocks and obfuscation.
 * Author: Lukas Grumlik - Rakosn1cek
 */

/// Calculates the Shannon entropy of a string to identify potential obfuscation.
pub fn calculate_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0usize; 256];
    let len = data.len() as f64;

    // Count occurrences of each byte
    for &b in data.as_bytes() {
        frequencies[b as usize] += 1;
    }

    // Apply the Shannon entropy formula
    frequencies.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Helper to identify if a specific line should be flagged for entropy.
pub fn is_high_entropy(line: &str) -> bool {
    let trimmed = line.trim();
    // Only analysing lines that are long enough to be significant (default 64)
    if trimmed.len() < 64 { 
        return false; 
    }
    
    // Using 4.5 as the default threshold for Base64 detection
    calculate_entropy(trimmed) > 4.5
}
