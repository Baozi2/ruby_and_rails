
### 使用pbkdf2 存储密码

```
class Admin < ActiveRecord::Base
  ##the table admins in db must has filed username and digest
  ##http://ruby-doc.org/stdlib-2.0.0/libdoc/openssl/rdoc/OpenSSL/PKCS5.html
  def digest=(password)
    ##strict_encode64 [a-zA-Z0-9+/ pad = ]http://www.rfc-base.org/txt/rfc-3548.txt
    salt = Base64.strict_encode64(OpenSSL::Random.random_bytes(16))
    iter = 20000
    key_len = 16
    dg = Base64.strict_encode64(OpenSSL::PKCS5.pbkdf2_hmac_sha1(password, salt, iter, key_len))
    super("#{dg}|#{salt}")
  end

  def check_password(password)
    right_digest, salt = self.digest.split('|')
    iter = 20000
    key_len = 16
    dg = Base64.strict_encode64(OpenSSL::PKCS5.pbkdf2_hmac_sha1(password, salt, iter, key_len))
    eql_time_cmp(right_digest, dg)
  end
  
  #avoid timing attacks
  def eql_time_cmp(a, b)
    unless a.length == b.length
      return false
    end
    cmp = b.bytes.to_a
    result = 0
    a.bytes.each_with_index {|c,i| #只要任一表达式的一位为 1，则结果的该位为 1。否则，结果的该位为 0。
      result |= c ^ cmp[i] #当且仅当只有一个表达式的某位上为 1 时，结果的该位才为 1。否则结果的该位为 0。
    }
    result == 0
  end

  class << self

    def create_administrator(username, password)
      admin = Admin.new(username: username)
      admin.digest = password
      admin.save
    end

    def check_administrator(username, password)
     admin = Admin.find_by(username:username)
     admin && admin.check_password(password)
    end
  end
end
```


