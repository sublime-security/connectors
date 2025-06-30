"""Virustotal feeds main file."""

from feeds import VirustotalFeeds

if __name__ == "__main__":
    connector = VirustotalFeeds()
    connector.run()
