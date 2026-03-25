# PGP, S/Mine

- $M$: Thông điệp gốc (Message)
- $H()$: Hàm băm (Hash function, ví dụ SHA-1 hoặc SHA-256)
- $KR_A$: Khóa bí mật của người gửi A (Private Key of A)
- $KU_A$: Khóa công khai của người gửi A (Public Key of A)
- $KR_B$: Khóa bí mật của người nhận B (Private Key of B)
- $KU_B$: Khóa công khai của người nhận B (Public Key of B)
- $K_s$ (hoặc $CEK$): Khóa phiên đối xứng dùng một lần (Session Key / Content Encryption Key)
- $E_{Key}(Data)$: Thao tác Mã hóa (Encryption) dữ liệu bằng một Khóa cụ thể
- $D_{Key}(Data)$: Thao tác Giải mã (Decryption) dữ liệu bằng một Khóa cụ thể
- $||$: Phép nối chuỗi dữ liệu (Concatenation)

---

### 1. Quy trình của PGP (Pretty Good Privacy)

### Phía Người gửi (A): Đóng gói

1. **Xác thực (Ký số):** A băm thông điệp và mã hóa bản băm bằng khóa bí mật của mình để tạo chữ ký ($Sig$).
    
    $$Sig = E_{KR_A}(H(M))$$
    
2. **Nén ($Z$):** PGP ghép thông điệp và chữ ký lại, sau đó nén (ZIP) thành một khối ($M_z$).
    
    $$M_z = Z(M || Sig)$$
    
3. **Mã hóa (Bảo mật):** A sinh khóa phiên $K_s$ và dùng nó mã hóa khối đã nén thành bản mã ($C$).
    
    $$C = E_{K_s}(M_z)$$
    
4. **Bọc khóa:** Khóa phiên $K_s$ được mã hóa bằng khóa công khai của B thành ($K_{enc}$).
    
    $$K_{enc} = E_{KU_B}(K_s)$$
    
5. **Định dạng (R64):** Chuyển đổi toàn bộ sang ASCII bằng thuật toán Radix-64.
    
    $$Output = R64(K_{enc} || C)$$
    
- **→ A gửi qua B khối dữ liệu:** $Output$

### Phía Người nhận (B): Mở gói

1. **Dịch định dạng:** B khôi phục dữ liệu nhị phân[cite: 847].
    
    $$R64^{-1}(Output) \rightarrow K_{enc} || C$$
    
2. **Giải mã khóa:** B lấy khóa bí mật của mình để mở khóa phiên.
    
    $$K_s = D_{KR_B}(K_{enc})$$
    
3. **Giải mã dữ liệu:** Có $K_s$, B mở bản mã để lấy khối nén.
    
    $$M_z = D_{K_s}(C)$$
    
4. **Giải nén ($Z^{-1}$):** B giải nén để tách thông điệp và chữ ký.
    
    $$Z^{-1}(M_z) \rightarrow M || Sig$$
    
5. **Xác minh chữ ký:** B băm $M$ và dùng khóa công khai của A để giải mã $Sig$. Nếu hai kết quả khớp nhau, thư an toàn.
    
    $$H(M) == D_{KU_A}(Sig)$$
    

---

### 2. Quy trình của S/MIME

- Với S/MIME, các bước tương tự nhưng được mô đun hóa thành các cấu trúc Cú pháp Thông điệp Mật mã (CMS).

### Phía Người gửi (A): Đóng gói

1. **Chuẩn hóa:** Chuyển $M$ về định dạng chuẩn mạng $M_{can}$.
2. **Xác thực (`SignedData`):** A tạo bản băm (Digest) và ký bằng khóa bí mật. Khối dữ liệu sau khi ký gọi chung là $M_{signed}$.
    
    $$Sig = E_{KR_A}(H(M_{can}))$$
    
    $$M_{signed} = M_{can} || Sig$$
    
3. **Mã hóa (`EnvelopedData`):** A sinh khóa $CEK$ và mã hóa $M_{signed}$ thành bản mã $C$. (Nếu dùng chuẩn S/MIME 4.0 `AuthEnvelopedData`, hệ thống sinh thêm thẻ $Tag$ để niêm phong bản mã) .
    
    $$C = E_{CEK}(M_{signed})$$
    
4. **Bọc khóa (`RecipientInfo`):** Khóa $CEK$ được mã hóa cho B.
    
    $$CEK_{enc} = E_{KU_B}(CEK)$$
    
5. **Định dạng Base64:** Mã hóa lại toàn bộ.
    
    $$Output = Base64(CEK_{enc} || C)$$
    
- **→ A gửi qua B khối dữ liệu:** $Output$

### Phía Người nhận (B): Mở gói

1. **Dịch định dạng:** B giải mã Base64 để lấy lại cấu trúc CMS[cite: 589].
2. **Giải mã khóa:** B tìm khối `RecipientInfo` của mình và giải mã lấy $CEK$.
    
    $$CEK = D_{KR_B}(CEK_{enc})$$
    
3. **Giải mã dữ liệu:** B dùng $CEK$ để giải mã $C$, thu lại khối $M_{signed}$.
    
    $$M_{signed} = D_{CEK}(C)$$
    
4. **Tách và Xác minh:** Từ $M_{signed}$, B tách ra $M_{can}$ và $Sig$.
    
    $$
    H(M_{can}) == D_{KU_A}(Sig)
    $$
    
5. **Kiểm tra PKI (Đặc thù của S/MIME):** B không tin ngay $KU_A$. Phần mềm của B phải xác minh chữ ký chứng chỉ của A lên tận Root CA và truy vấn OCSP/CRL xem chứng chỉ có bị thu hồi không.
