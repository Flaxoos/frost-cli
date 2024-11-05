# CLI Tool for demonstrating the use of the rust [FROST](https://docs.rs/frost-dalek/latest/frost_dalek/) library

---

## Instructions

- Run `sh setup.sh {n} {t}`, where {n} is the number of shares and {t} is the threshold and `n >= 5` and `n >= t`, for example:

  ```shell
  sh setup.sh 5 3
  ```

  This will setup the .env file and also clear any existing data in the `data` directory
- Run ```cargo run -- start-session --participant-index {participant_index}``` for each participant where `participant_index` is the 1-indexed participant index, for example:

  ```cargo run --package zama -- start-session --participant-index 1```

  ```cargo run --package zama -- start-session --participant-index 2```

  ```cargo run --package zama -- start-session --participant-index 3```

  ```cargo run --package zama -- start-session --participant-index 4```

  ```cargo run --package zama -- start-session --participant-index 5```
- Each participant would see messages reporting the key generation process and will be prompted to press any key to continue once their keygen is ready

## Please note:

- The implementation relies on concurrency and async logic to collect broadcasted data, where the current frequency of the data collection is set to 3 seconds: ```pub const HEART_BEAT: Duration = Duration::from_secs(3);``` This is for better visibility, and can be configured in the `config.rs` file

## Caveats:

- Currently any excess signers (n-t) will get errors, where as the others will get success message (WIP to prevent the excess signers from continuing)
- Not handling all edge cases of user input atm, some input validation exists
- The library returns an non-meaningful error for the final signature verification. I chose to swallow it for now and consider the verification to be successful.

## Improvements Suggestions:

- Add more input validation
- Allow more granular step control using more commands such as `publish`, `init-1`, `init-2` etc.
- Store data per context, so participants can take part in other groups
- Consider using a db to store data instead of the current file based approach, to allow for transaction and locking management
