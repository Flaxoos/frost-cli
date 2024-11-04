use assert_cmd::Command;
use indoc::formatdoc;
use predicates::prelude::PredicateStrExt;
use std::str;

#[test]
fn test_default_behavior() {
    let cmds = (1..5)
        .for_each(|i| {
            let mut binding = Command::cargo_bin("zama")
                .unwrap();
            let cmd = binding
                .arg("start-session")
                .arg("--participant-index")
                .arg(i.to_string());


            // Capture the output
            let output = cmd.output().expect("Failed to execute command");

            // Convert stdout to string and print it
            let stdout = str::from_utf8(&output.stdout).expect("Failed to parse stdout as UTF-8");
            let stderr = str::from_utf8(&output.stderr).expect("Failed to parse stderr as UTF-8");

            // Print outputs for debugging
            println!("Stdout:\n{}", stdout);
            println!("Stderr:\n{}", stderr);


            cmd.assert().stdout(formatdoc! {"
                Starting session for participant {i}
                Creating participant {i}
                Participant {i} saved to participant_{i}.json
                Starting DKG for participant {i}
                > Type 'sign', when you are ready to sign. Type 'help' or 'exit' to continue: sign
            ", i = i});
            println!("Ok")
        });
}
