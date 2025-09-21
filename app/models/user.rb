class User < ApplicationRecord
  # Name validations - letters, spaces, hyphens, and apostrophes only, max 64 characters, no SQL injection
  validates :first_name, presence: true, 
            format: { with: /\A[a-zA-Z\s\-']+\z/, message: "can only contain letters, spaces, hyphens, and apostrophes" },
            length: { maximum: 64 }
  validates :last_name, presence: true, 
            format: { with: /\A[a-zA-Z\s\-']+\z/, message: "can only contain letters, spaces, hyphens, and apostrophes" },
            length: { maximum: 64 }
  
  # Custom validation to prevent SQL injection and malicious input
  validate :prevent_sql_injection

  # Email validations - real email format, max 64 characters, unique
  validates :email, presence: true, 
            format: { with: /\A[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\z/, message: "must be a valid email address with proper domain" }, 
            uniqueness: { case_sensitive: false },
            length: { maximum: 64 }


  # Normalize email to lowercase before saving
  before_save :normalize_email

  private
  
  def normalize_email
    self.email = email&.strip&.downcase
  end
  
  def prevent_sql_injection
    # List of SQL keywords and dangerous patterns to block
    # Only include keywords that are dangerous in SQL context
    sql_keywords = %w[
      select insert update delete drop create alter database
      union where from into values set having group order by
      and or not like in exists between is null
      exec execute sp_ xp_ cmdshell
      javascript vbscript onload onerror
      alert confirm prompt document window
      union select concat char ascii substring
      information_schema sys.tables sys.columns
      load_file into outfile dumpfile
      benchmark sleep waitfor delay
      pg_sleep pg_database pg_user
      mysql.user mysql.db
    ]
    
    # SQL keywords that are dangerous in context
    sql_context_keywords = %w[
      table script
    ]
    
    # JavaScript and XSS related keywords - only block in malicious context
    js_keywords = %w[
      script javascript vbscript jscript
      alert confirm prompt document window
      location href src expression url
      data text html css style iframe object
      embed applet form input textarea button
      select option optgroup fieldset legend
      label img svg canvas audio video source
      track map area link meta title base
      head body html div span p h1 h2 h3
      h4 h5 h6 ul ol li dl dt dd table
      tr td th thead tbody tfoot caption
      col colgroup
    ]
    
    # Event handler keywords - always block these
    event_handlers = %w[
      onload onerror onclick onmouseover onfocus onblur
      onchange onsubmit onreset onselect onkeydown
      onkeyup onkeypress onmousedown onmouseup
      onmousemove onmouseout onmouseenter
      onmouseleave oncontextmenu ondblclick
      onwheel onresize onscroll onbeforeunload
      onunload onloadstart onloadend onprogress
      onabort oncanplay oncanplaythrough
      ondurationchange onemptied onended
      onloadeddata onloadedmetadata onpause
      onplay onplaying onratechange onseeked
      onseeking onstalled onsuspend ontimeupdate
      onvolumechange onwaiting
    ]
    
    # Check first_name and last_name for SQL injection and XSS patterns
    [first_name, last_name].each_with_index do |field, index|
      field_name = index == 0 ? :first_name : :last_name
      next if field.blank?
      
      # Check for SQL keywords in context (case insensitive)
      # Only flag if the keyword appears as a standalone word or in SQL context
      sql_keywords.each do |keyword|
        # Create a regex that matches the keyword as a whole word or in SQL context
        keyword_pattern = /\b#{Regexp.escape(keyword)}\b/i
        if field.match?(keyword_pattern)
          errors.add(field_name, "contains prohibited content")
          break
        end
      end
      
      # Check for context-sensitive SQL keywords
      sql_context_keywords.each do |keyword|
        # Only block if the keyword appears with dangerous SQL context
        dangerous_sql_context_patterns = [
          /drop\s+#{Regexp.escape(keyword)}/i,      # DROP TABLE, DROP SCRIPT
          /create\s+#{Regexp.escape(keyword)}/i,    # CREATE TABLE, CREATE SCRIPT
          /alter\s+#{Regexp.escape(keyword)}/i,     # ALTER TABLE, ALTER SCRIPT
          /#{Regexp.escape(keyword)}\s+\(/i,        # TABLE(, SCRIPT(
          /#{Regexp.escape(keyword)}\s+where/i,     # TABLE WHERE, SCRIPT WHERE
          /#{Regexp.escape(keyword)}\s+set/i,       # TABLE SET, SCRIPT SET
          /#{Regexp.escape(keyword)}\s+from/i,      # TABLE FROM, SCRIPT FROM
          /#{Regexp.escape(keyword)}\s+into/i,      # TABLE INTO, SCRIPT INTO
          /#{Regexp.escape(keyword)}\s+values/i,    # TABLE VALUES, SCRIPT VALUES
        ]
        
        if dangerous_sql_context_patterns.any? { |pattern| field.match?(pattern) }
          errors.add(field_name, "contains prohibited content")
          break
        end
      end
      
      # Check for event handlers (always block these)
      event_handlers.each do |handler|
        handler_pattern = /\b#{Regexp.escape(handler)}\b/i
        if field.match?(handler_pattern)
          errors.add(field_name, "contains prohibited content")
          break
        end
      end
      
      # Check for JavaScript/XSS keywords only in malicious context
      # Allow standalone names but block when used with dangerous patterns
      js_keywords.each do |keyword|
        # Only block if the keyword appears with dangerous context
        dangerous_context_patterns = [
          /<#{Regexp.escape(keyword)}/i,           # <script, <html, etc.
          /#{Regexp.escape(keyword)}\s*:/i,        # javascript:, data:, etc.
          /#{Regexp.escape(keyword)}\s*\(/i,       # alert(, confirm(, etc.
          /#{Regexp.escape(keyword)}\s*=/i,        # src=, href=, etc.
          /#{Regexp.escape(keyword)}\s*>/i,        # </script>, </html>, etc.
        ]
        
        if dangerous_context_patterns.any? { |pattern| field.match?(pattern) }
          errors.add(field_name, "contains prohibited content")
          break
        end
      end
      
      # Check for common SQL injection and XSS patterns
      dangerous_patterns = [
        # SQL injection patterns
        /['"]\s*;/,               # Quotes followed by semicolon
        /['"]\s*--/,              # Quotes followed by SQL comment
        /['"]\s*drop/i,           # Quotes followed by DROP
        /['"]\s*insert/i,         # Quotes followed by INSERT
        /['"]\s*update/i,         # Quotes followed by UPDATE
        /['"]\s*delete/i,         # Quotes followed by DELETE
        /['"]\s*union/i,          # Quotes followed by UNION
        /[;]/,                     # Semicolons
        /--/,                      # SQL comments
        /\/\*.*\*\//,             # Block comments
        /union\s+select/i,        # UNION SELECT
        /or\s+1\s*=\s*1/i,        # OR 1=1
        /and\s+1\s*=\s*1/i,       # AND 1=1
        /drop\s+table/i,          # DROP TABLE
        /insert\s+into/i,         # INSERT INTO
        /update\s+set/i,          # UPDATE SET
        /delete\s+from/i,         # DELETE FROM
        /create\s+table/i,        # CREATE TABLE
        /alter\s+table/i,         # ALTER TABLE
        /exec\s*\(/i,             # EXEC(
        /execute\s*\(/i,          # EXECUTE(
        
        # JavaScript/XSS patterns
        /<script/i,               # <script tag
        /<\/script>/i,            # </script> tag
        /javascript\s*:/i,        # javascript: protocol
        /vbscript\s*:/i,          # vbscript: protocol
        /data\s*:\s*text\s*\/\s*html/i, # data:text/html
        /expression\s*\(/i,       # CSS expression(
        /url\s*\(\s*javascript/i, # url(javascript
        /on\w+\s*=/i,             # Event handlers (onload=, onclick=, etc.)
        /<iframe/i,               # <iframe tag
        /<object/i,               # <object tag
        /<embed/i,                # <embed tag
        /<applet/i,               # <applet tag
        /<form/i,                 # <form tag
        /<input/i,                # <input tag
        /<textarea/i,             # <textarea tag
        /<button/i,               # <button tag
        /<select/i,               # <select tag
        /<img/i,                  # <img tag
        /<svg/i,                  # <svg tag
        /<canvas/i,               # <canvas tag
        /<audio/i,                # <audio tag
        /<video/i,                # <video tag
        /<link/i,                 # <link tag
        /<meta/i,                 # <meta tag
        /<style/i,                # <style tag
        /<link/i,                 # <link tag
        /&#x?[0-9a-f]+;/i,        # HTML entities (hex)
        /&[a-z]+;/i,              # HTML entities (named)
        /\\x[0-9a-f]{2}/i,        # Hex encoding
        /\\u[0-9a-f]{4}/i,        # Unicode encoding
      ]
      
      dangerous_patterns.each do |pattern|
        if field.match?(pattern)
          errors.add(field_name, "contains prohibited content")
          break
        end
      end
    end
  end
end
