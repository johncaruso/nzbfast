# Homebrew formula for nzbfast (tap: brew install nzbfast/tap/nzbfast).
# SHA256s + version are filled in by the release workflow; the template
# lives here so the tap can be regenerated deterministically.
class Nzbfast < Formula
  desc "Fastest Usenet (NZB) downloader - pipelined, one-pass verify + extract"
  homepage "https://github.com/nzbfast/nzbfast"
  version "1.0.10"
  license "GPL-3.0-or-later"

  on_macos do
    on_arm do
      url "https://github.com/nzbfast/nzbfast/releases/download/v#{version}/nzbfast-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_ARM64_MACOS_SHA"
    end
    on_intel do
      url "https://github.com/nzbfast/nzbfast/releases/download/v#{version}/nzbfast-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_X86_MACOS_SHA"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/nzbfast/nzbfast/releases/download/v#{version}/nzbfast-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_ARM64_LINUX_SHA"
    end
    on_intel do
      url "https://github.com/nzbfast/nzbfast/releases/download/v#{version}/nzbfast-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_X86_LINUX_SHA"
    end
  end

  # PAR2 repair and RAR extraction are fully native - no tool
  # dependencies. (A user-installed par2/unrar on PATH is still honored
  # as a fallback, but nothing requires one.)

  def install
    bin.install "nzbfast"
  end

  service do
    run [opt_bin/"nzbfast", "serve", "--config", etc/"nzbfast/config.json",
         "--out", var/"nzbfast/downloads", "--watch", var/"nzbfast/watch"]
    keep_alive true
    log_path var/"log/nzbfast.log"
    error_log_path var/"log/nzbfast.log"
  end

  def caveats
    <<~EOS
      Add your Usenet server(s) to:
        #{etc}/nzbfast/config.json
      (copy the template from the repo's packaging/config.example.json)
      Then: brew services start nzbfast - UI at http://localhost:6789
    EOS
  end

  test do
    assert_match "nzbfast", shell_output("#{bin}/nzbfast --help")
  end
end
