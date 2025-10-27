# cryx.cr
require "file_utils"
require "base32"
require "base64"
require "openssl"
require "json"

# --- Config ---
READABLE_EXTS = [".txt", ".md", ".json", ".html", ".xml", ".csv", ".yaml", ".yml", ".ini"]
SPINNER_FRAMES = ["|", "/", "-", "\\"]

# --- Spinner ---
class Spinner
  getter running = false

  def initialize(@text : String, @current : Int32, @total : Int32)
  end

  def start
    @running = true
    spawn do
      i = 0
      while @running
        print "\r#{SPINNER_FRAMES[i % SPINNER_FRAMES.size]} #{@text} (#{@current}/#{@total})"
        # update terminal title
        print "\033]0;Renaming files... #{@current}/#{@total}\007"
        i += 1
        sleep 0.1
      end
    end
  end

  def stop
    @running = false
    print "\r✓ #{@text} (#{@current}/#{@total}) done!          \n"
  end
end

# --- Notifications ---
def notify(title : String, message : String)
  if Crystal::System::Platform.windows?
    # Windows toast via PowerShell (best-effort)
    # Escape single quotes
    t = title.gsub("'", "''")
    m = message.gsub("'", "''")
    cmd = %($(powershell -NoProfile -Command \
      "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]; \
      $template=[Windows.UI.Notifications.ToastTemplateType]::ToastText02; \
      $xml=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template); \
      $txt=$xml.GetElementsByTagName('text'); \
      $txt.Item(0).AppendChild($xml.CreateTextNode('#{t}'))|Out-Null; \
      $txt.Item(1).AppendChild($xml.CreateTextNode('#{m}'))|Out-Null; \
      $toast=[Windows.UI.Notifications.ToastNotification]::new($xml); \
      [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('CrystalTool').Show($toast)"])
    system(cmd)
  else
    # Linux: use notify-send if present
    system("which notify-send > /dev/null 2>&1")
    if $?.exitstatus == 0
      system("notify-send #{title.inspect} #{message.inspect}")
    end
  end
end

# --- Crypto helpers (AES-256-CBC) ---
def derive_key(password : String) : Bytes
  OpenSSL::Digest::SHA256.digest(password) # returns 32 bytes key
end

def encrypt_text(plain : String, password : String) : String
  cipher = OpenSSL::Cipher.new("aes-256-cbc")
  cipher.encrypt
  key = derive_key(password)
  iv = Random::Secure.random_bytes(16)
  cipher.key = key
  cipher.iv  = iv
  encrypted = cipher.update(plain) + cipher.final
  Base64.strict_encode(iv + encrypted) # store IV + ciphertext, base64 encoded
end

def decrypt_text(cipher_b64 : String, password : String) : String
  raw = Base64.decode(cipher_b64)
  iv = raw[0,16]
  enc = raw[16..]
  cipher = OpenSSL::Cipher.new("aes-256-cbc")
  cipher.decrypt
  cipher.key = derive_key(password)
  cipher.iv  = iv
  (cipher.update(enc) + cipher.final)
end

# --- File operations ---
def count_readable_files(folder : String, total = 0) : Int32
  return total unless Dir.exists?(folder)
  Dir.each_child(folder) do |entry|
    path = File.join(folder, entry)
    if File.directory?(path)
      total = count_readable_files(path, total)
    elsif File.file?(path)
      ext = File.extname(path).downcase
      total += 1 if READABLE_EXTS.includes?(ext)
    end
  end
  total
end

# encode (base32) then encrypt and write payload containing original name
def encode_and_encrypt_file(path : String, password : String) : Int32
  content = File.read(path)
  encoded = Base32.encode(content)
  payload = {"name" => File.basename(path), "data" => encoded}.to_json
  encrypted = encrypt_text(payload, password)
  File.write(path, encrypted)
  0
end

# decrypt, parse JSON payload, decode base32, restore original filename & content
def decrypt_and_restore_file(path : String, password : String, folder : String) : Bool
  cipher_text = File.read(path)
  begin
    payload_json = decrypt_text(cipher_text, password)
    json = JSON.parse(payload_json)
    orig_name = json["name"].as_s
    encoded = json["data"].as_s
    original_content = Base32.decode(encoded)
    dest = File.join(folder, orig_name)
    File.write(dest, original_content)
    true
  rescue ex
    STDERR.puts "⚠️ Decryption/restore failed for #{path}: #{ex.message}"
    false
  end
end

# --- Recursive processing ---
def rename_encode_encrypt(folder : String, counter : Int32, total : Int32, password : String, depth = 0) : Int32
  indent = "  " * depth
  puts "#{indent}📂 #{folder}"

  Dir.each_child(folder) do |entry|
    path = File.join(folder, entry)
    begin
      if File.directory?(path)
        counter = rename_encode_encrypt(path, counter, total, password, depth + 1)
      elsif File.file?(path)
        ext = File.extname(path).downcase
        if READABLE_EXTS.includes?(ext)
          counter += 1
          new_path = File.join(folder, File.basename(entry, ext) + ".cryx")
          spinner = Spinner.new("Encoding & Encrypting #{entry}", counter, total)
          spinner.start

          encode_and_encrypt_file(path, password)
          File.rename(path, new_path)

          spinner.stop
        else
          puts "#{indent}  ❌ Skipped: #{entry} (not readable)"
        end
      end
    rescue ex
      puts "#{indent}  ⚠️ Error on #{entry}: #{ex.message}"
    end
  end

  counter
end

# When decoding: look for .cryx files and restore
def decode_and_restore(folder : String, counter : Int32, total : Int32, password : String, depth = 0) : Int32
  indent = "  " * depth
  puts "#{indent}📂 #{folder}"

  Dir.each_child(folder) do |entry|
    path = File.join(folder, entry)
    begin
      if File.directory?(path)
        counter = decode_and_restore(path, counter, total, password, depth + 1)
      elsif File.file?(path)
        if File.extname(path).downcase == ".cryx"
          counter += 1
          spinner = Spinner.new("Decrypting & Restoring #{entry}", counter, total)
          spinner.start

          success = decrypt_and_restore_file(path, password, folder)
          spinner.stop

          if success
            # Remove the .cryx file after successful restore
            File.delete(path)
            puts "  Restored and removed: #{entry}"
          else
            puts "  ⚠️ Failed to restore: #{entry}"
          end
        else
          puts "#{indent}  ❌ Skipped: #{entry} (not .cryx)"
        end
      end
    rescue ex
      puts "#{indent}  ⚠️ Error on #{entry}: #{ex.message}"
    end
  end

  counter
end

# --- Utility: read password (best-effort hidden input on Unix) ---
def read_password(prompt : String = "Password: ") : String
  if Crystal::System::Platform.windows?
    print "#{prompt}"
    STDOUT.flush
    STDIN.gets.not_nil!.chomp
  else
    # hide input using stty
    print "#{prompt}"
    STDOUT.flush
    system("stty -echo")
    pwd = STDIN.gets.not_nil!.chomp
    system("stty echo")
    puts # newline after hidden input
    pwd
  end
end



# --- Main ---
decode_mode = false
folder = "."
# parse args naive: allow: [--decode|-d] [path]
args = ARGV.dup
if args.includes("--decode") || args.includes("-d")
  decode_mode = true
  args = args.reject { |a| a == "--decode" || a == "-d" }
end
folder = args[0]? || "."

unless Dir.exists?(folder)
  STDERR.puts "Error: folder not found -> #{folder}"
  exit 1
end

if decode_mode
  # Count total .cryx files to restore
  total = 0
  Dir.each_child(folder, follow_symlinks: true) do |entry|
    # use recursive count function limited to .cryx
  end
  # reuse recursive function to count .cryx
  def count_cryx(folder : String, total = 0) : Int32
    return total unless Dir.exists?(folder)
    Dir.each_child(folder) do |entry|
      path = File.join(folder, entry)
      if File.directory?(path)
        total = count_cryx(path, total)
      elsif File.file?(path)
        total += 1 if File.extname(path).downcase == ".cryx"
      end
    end
    total
  end
  total = count_cryx(folder)
  puts "Found #{total} .cryx files to decrypt and restore.\n\n"
  if total == 0
    puts "Nothing to decode."
    exit 0
  end

  password = read_password("Enter decryption password: ")
  decode_and_restore(folder, 0, total, password)
  print "\033]0;✅ Done restoring #{total} files!\007"
  puts "\n🎉 All done (decode/restore)."
  notify("Crystal Renamer", "✅ Restored #{total} files from .cryx")
else
  total = count_readable_files(folder)
  puts "Found #{total} readable files to encode/encrypt and rename.\n\n"
  if total == 0
    puts "No readable files found."
    notify("Crystal Renamer", "No readable files were found.")
    exit 0
  end

  password = read_password("Enter encryption password: ")
  rename_encode_encrypt(folder, 0, total, password)
  print "\033]0;✅ Done encoding & encrypting #{total} files!\007"
  puts "\n🎉 All readable files encoded (Base32), encrypted, and renamed to .cryx!"
  notify("Crystal Renamer", "✅ Encoded & encrypted #{total} files to .cryx")
end
