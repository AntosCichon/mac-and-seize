from argparse import ArgumentParser, Namespace

def get_cli_args() -> Namespace:
    parser = ArgumentParser(
        prog = "PROGRAM NAME",
        usage = "USAGE",
        description="DESCRIPTION",
        epilog="EPILOG",
        # formatter_class=argparse.RawDescriptionHelpFormatter,
        )
    
    parser.add_argument(
        "-c", "--config",
        default = "config.toml",
        type = str,
        help = "Path to the configuration file (default: config.toml)",
        metavar = "PATH",
        dest = "setup__config_path",
        )

    return parser.parse_args()