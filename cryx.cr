# rename_readable_to_cryx_base32.cr
require "file_utils"
require "base32"

# --- Config ---
READABLE_EXTS = [".txt", ".md", ".json", ".html", ".xml", ".csv", ".yaml", ".yml", ".ini"]
SPINNER_FRAMES = ["|", "/", "-", "\\"]

# --- Spinner Class ---
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
        print "\033]0;Renaming files... #{@current}/#{@total}\007" # terminal title
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
    system(%(powershell -Command "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]; \
      $template=[Windows.UI.Notifications.ToastTemplateType]::ToastText02; \
      $xml=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template); \
      $txt=$xml.GetElementsByTagName('text'); \
      $txt.Item(0).AppendChild($xml.CreateTextNode('#{title}'))|Out-Null; \
      $txt.Item(1).AppendChild($xml.CreateTextNode('#{message}'))|Out-Null; \
      $toast=[Windows.UI.Notifications.ToastNotification]::new($xml); \
      [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('CrystalTool').Show($toast)") )
  else
    system("notify-send '#{title}' '#{message}'") if system("which notify-send > /dev/null 2>&1")
  end
end

# --- Count readable files ---
def count_readable_files(folder : String, total = 0) : Int32
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

# --- Encode file content with Base32 ---
def encode_file_base32(file_path : String)
  content = File.read(file_path)
  encoded = Base32.encode(content)
  File.write(file_path, encoded)
end

# --- Recursive rename & encode ---
def rename_readable_files(folder : String, counter : Int32, total : Int32, depth = 0) : Int32
  indent = "  " * depth
  puts "#{indent}📂 #{folder}"

  Dir.each_child(folder) do |entry|
    path = File.join(folder, entry)
    begin
      if File.directory?(path)
        counter = rename_readable_files(path, counter, total, depth + 1)
      elsif File.file?(path)
        ext = File.extname(path).downcase
        if READABLE_EXTS.includes?(ext)
          counter += 1
          new_path = File.join(folder, File.basename(entry, ext) + ".cryx")

          spinner = Spinner.new("Encoding & renaming #{entry}", counter, total)
          spinner.start

          # Encode file content to Base32
          encode_file_base32(path)

          # Rename the file
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

# --- Main ---
folder = ARGV[0]? || "."
total_files = count_readable_files(folder)
puts "Found #{total_files} readable files to encode and rename.\n\n"

if total_files > 0
  rename_readable_files(folder, 0, total_files)
  print "\033]0;✅ Done encoding & renaming #{total_files} files!\007"
  puts "\n🎉 All readable files encoded (Base32) and renamed to .cryx!"
  notify("Crystal Renamer", "✅ Encoded and renamed #{total_files} readable files to .cryx")
else
  puts "No readable files found."
  notify("Crystal Renamer", "No readable files were found.")
end
