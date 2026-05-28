import argparse
import zipfile


def main():
    parser = argparse.ArgumentParser(description="Build a LockItPDF recovery package")
    parser.add_argument("--output", required=True)
    parser.add_argument("--encrypted-file", required=True)
    parser.add_argument("--encrypted-name", required=True)
    parser.add_argument("--helper-file", required=True)
    parser.add_argument("--readme-file", required=True)
    args = parser.parse_args()

    with zipfile.ZipFile(args.output, "w", compression=zipfile.ZIP_DEFLATED) as package:
        package.write(args.encrypted_file, args.encrypted_name)
        package.write(args.helper_file, "open_recovery.html")
        package.write(args.readme_file, "README.txt")


if __name__ == "__main__":
    main()
