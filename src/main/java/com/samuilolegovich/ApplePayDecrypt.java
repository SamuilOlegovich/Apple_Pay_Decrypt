package com.samuilolegovich;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iwis.planetakino.payservice.PayServiceApplication;
import com.iwis.planetakino.payservice.web.model.request.liqpay.apple.AppleEncodeCardData;
import com.iwis.planetakino.payservice.web.model.request.liqpay.apple.DataApplePay;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class ApplePayDecrypt {
    private static final byte[] ALG_IDENTIFIER_BYTES = "id-aes256-GCM".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] APPLE_OEM = "Apple".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] COUNTER = { 0x00, 0x00, 0x00, 0x01 };

    @Value("${app.apple.oid}")
    private static String OID;                          //   1.2.840.113635.100.6.32
    @Value("${app.apple.merchant-id}")
    public static String MERCHANT_ID;                   //   MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJJwyw.....
    @Value("${app.apple.password-fo-key}")
    private static String passwordFoKey;                //   GetITbyYouselF
    @Value("${app.apple.path-fo-certificate-pk8}")
    public static String PATH_CERTIFICATE_PK8;          //   /Users/samuilolegovich/Work/Cer/AppleRootCA-G3
    @Value("${app.apple.path-fo-certificate-jsk}")
    public static String PATH_CERTIFICATE_JKS;          //   /Users/samuilolegovich/Work/Cer/AppleJKS


    private static PrivateKey merchantPrivateKey;
    private static KeyStore keyStore;


    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }




    public static AppleEncodeCardData decrypt(DataApplePay dataApplePay) {
        try {
            String key = MERCHANT_ID
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] merchantPrivateKeyBytes = Base64.decodeBase64(key);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(merchantPrivateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", PROVIDER_NAME);
            merchantPrivateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            // Загрузите корневой сертификат Apple-------------------->
            keyStore = KeyStore.getInstance("BKS");
            keyStore.load(new FileInputStream(PATH_CERTIFICATE_PK8), passwordFoKey.toCharArray());
            return unwrap(dataApplePay);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }



    @SuppressWarnings({ "unused"})
    public static AppleEncodeCardData unwrap(DataApplePay dataApplePay) throws Exception {
        // Продавцы должны использовать поле «версия», чтобы определить,
        // как проверить и расшифровать полезные данные сообщения.
        // На данный момент единственная опубликованная версия - «EC_v1»,
        // которая демонстрируется здесь.
        String version = dataApplePay.getVersion();

        byte[] ephemeralPublicKeyBytes = Base64.decodeBase64(dataApplePay.getHeader().get("ephemeralPublicKey"));
        byte[] transactionIdBytes = Hex.decode(dataApplePay.getHeader().get("transactionId"));
        byte[] signatureBytes = Base64.decodeBase64(dataApplePay.getSignature());
        byte[] dataBytes = Base64.decodeBase64(dataApplePay.getData());
//        JsonObject headerJsonObject = jsonObject.get(PAYMENT_HEADER).getAsJsonObject();

        // Продавцы, у которых есть более одного сертификата, могут использовать поле 'publicKeyHash',
        // чтобы определить, какой сертификат использовался для шифрования этой полезной нагрузки.
        byte[] publicKeyHash = Base64.decodeBase64(dataApplePay.getHeader().get("publicKeyHash"));

        // Данные приложения - это условное поле, которое присутствует,
        // когда продавец предоставил их в iOS SDK.
        byte[] signedBytes = ArrayUtils.addAll(ephemeralPublicKeyBytes, dataBytes);
        byte[] applicationDataBytes = null;

        signedBytes = ArrayUtils.addAll(signedBytes, transactionIdBytes);
        signedBytes = ArrayUtils.addAll(signedBytes, applicationDataBytes);

        CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(signedBytes), signatureBytes);

        // Проверить путь к сертификату
        Store certificateStore = signedData.getCertificates();
        List<X509Certificate> certificates = new ArrayList<X509Certificate>();
        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
        certificateConverter.setProvider(PROVIDER_NAME);

        for (Object o : certificateStore.getMatches(null)) {
            X509CertificateHolder certificateHolder = (X509CertificateHolder) o;
            certificates.add(certificateConverter.getCertificate(certificateHolder));
        }

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", PROVIDER_NAME);
        CertPath certificatePath = certificateFactory.generateCertPath(certificates);

        PKIXParameters params = new PKIXParameters(keyStore);
        params.setRevocationEnabled(false);

        // TODO: Сертификат тестирования не содержит списков отзыва сертификатов.
        // Продавцы должны выполнять проверки отзыва на производстве.
        // TODO: проверьте атрибуты сертификата в соответствии с инструкциями на
        // https://developer.apple.com/library/ios/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html#//apple_ref/doc/uid/TP40014929

        CertPathValidator validator = CertPathValidator.getInstance("PKIX", PROVIDER_NAME);
        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(certificatePath, params);

        // Проверить подпись
        SignerInformationStore signerInformationStore = signedData.getSignerInfos();
        boolean verified = false;

        for (Object o : signerInformationStore.getSigners()) {
            SignerInformation signer = (SignerInformation) o;
            Collection<?> matches = certificateStore.getMatches(signer.getSID());

            if (!matches.isEmpty()) {
                X509CertificateHolder certificateHolder = (X509CertificateHolder) matches.iterator().next();
                SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider(PROVIDER_NAME).build(certificateHolder);

                if (signer.verify(signerInformationVerifier)) {
//                    DERSequence sequence = (DERSequence) signer.getSignedAttributes().get(CMSAttributes.signingTime).toASN1Primitive();
//                    ASN1UTCTime signingTime = (ASN1UTCTime) set.getObjectAt(0).toASN1Primitive();
                    DERSequence sequence = (DERSequence) signer.getSignedAttributes().get(CMSAttributes.signingTime).toASN1Object();
                    DERSet set = (DERSet) sequence.getObjectAt(1);
                    ASN1UTCTime signingTime = (ASN1UTCTime) set.getObjectAt(0).getDERObject().toASN1Object();
                    // Продавцы могут проверить время подписания этого платежа, чтобы определить его актуальность.
//                    System.out.println("Signature verified. Signing time is " + signingTime.getDate());
                    verified = true;
                }
            }
        }

        if (verified) {
            // Эфемерный открытый ключ
            KeyFactory keyFactory = KeyFactory.getInstance("EC", PROVIDER_NAME);
            PublicKey ephemeralPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(ephemeralPublicKeyBytes));

            // Ключевое соглашение
            String asymmetricKeyInfo = "ECDH";
            KeyAgreement agreement = KeyAgreement.getInstance(asymmetricKeyInfo, PROVIDER_NAME);

            agreement.init(merchantPrivateKey);
            agreement.doPhase(ephemeralPublicKey, true);

            byte[] sharedSecret = agreement.generateSecret();
            byte[] derivedSecret = performKDF(sharedSecret, extractMerchantIdFromCertificateOid());

            // Расшифровать платежные данные
            String symmetricKeyInfo = "AES/GCM/NoPadding";
            Cipher cipher = Cipher.getInstance(symmetricKeyInfo, PROVIDER_NAME);
            SecretKeySpec key = new SecretKeySpec(derivedSecret, cipher.getAlgorithm());
            IvParameterSpec ivspec = new IvParameterSpec(new byte[16]);
            cipher.init(Cipher.DECRYPT_MODE, key, ivspec);
            byte[] decryptedPaymentData = cipher.doFinal(dataBytes);

            // Полезная нагрузка JSON
            String data = new String(decryptedPaymentData, StandardCharsets.UTF_8);
            return new ObjectMapper().readValue(data, AppleEncodeCardData.class);
        } else {
            return null;
        }
    }



    private static byte[] performKDF(byte[] sharedSecret, byte[] merchantId) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(COUNTER);
        baos.write(sharedSecret);
        baos.write(ALG_IDENTIFIER_BYTES.length);
        baos.write(ALG_IDENTIFIER_BYTES);
        baos.write(APPLE_OEM);
        baos.write(merchantId);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA256", PROVIDER_NAME);
        return messageDigest.digest(baos.toByteArray());
    }



    @SuppressWarnings("unused")
    private static byte[] performKDF(byte[] sharedSecret, String merchantId) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA256", PROVIDER_NAME);
        return performKDF(sharedSecret, messageDigest.digest(merchantId.getBytes(StandardCharsets.UTF_8)));
    }



    protected static byte[] extractMerchantIdFromCertificateOid() throws Exception {
        KeyStore vKeyStore = KeyStore.getInstance("JKS");
        vKeyStore.load(new FileInputStream(PATH_CERTIFICATE_JKS), "".toCharArray());
        Enumeration<String> aliases = vKeyStore.aliases();
        String alias = null;

        while (aliases.hasMoreElements()) {
            alias = aliases.nextElement();
        }

        X509Certificate cert = (X509Certificate) vKeyStore.getCertificate(alias);
        byte[] merchantIdentifierTlv = cert.getExtensionValue(OID);
        byte[] merchantIdentifier = new byte[64];
        System.arraycopy(merchantIdentifierTlv, 4, merchantIdentifier, 0, 64);
        return Hex.decode(merchantIdentifier);
    }
}
