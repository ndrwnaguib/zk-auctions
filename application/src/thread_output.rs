/// Custom print macros that add thread tags to all output
/// This allows us to prefix all output from threads without modifying host code

/// Macro for thread-tagged println
#[macro_export]
macro_rules! tprintln {
    ($tag:expr, $($arg:tt)*) => {
        println!("[{}] {}", $tag, format_args!($($arg)*));
    };
}

/// Macro for thread-tagged eprintln
#[macro_export]
macro_rules! teprintln {
    ($tag:expr, $($arg:tt)*) => {
        eprintln!("[{}] {}", $tag, format_args!($($arg)*));
    };
}

/// Macro for thread-tagged print
#[macro_export]
macro_rules! tprint {
    ($tag:expr, $($arg:tt)*) => {
        print!("[{}] {}", $tag, format_args!($($arg)*));
    };
}

/// Macro for thread-tagged eprint
#[macro_export]
macro_rules! teprint {
    ($tag:expr, $($arg:tt)*) => {
        eprint!("[{}] {}", $tag, format_args!($($arg)*));
    };
}