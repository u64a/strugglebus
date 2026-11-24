# Release signing

Google Play requires an Android App Bundle signed with an upload key. The upload key is separate from the app-signing key retained by Google Play App Signing.

Create `keystore.properties` in the repository root (it is ignored by Git):

```properties
storeFile=C:\\Users\\YOUR_USER\\.android\\struggleapp-upload.jks
storePassword=<upload-keystore-password>
keyAlias=struggleapp-upload
keyPassword=<upload-key-password>
```

Generate the upload key once and back it up outside the development machine:

```powershell
keytool -genkeypair -v -keystore "$HOME\.android\struggleapp-upload.jks" -alias struggleapp-upload -keyalg RSA -keysize 4096 -validity 10000
```

Never commit the keystore or `keystore.properties`. Losing the upload key requires the Google Play upload-key reset process.

Build the signed bundle with:

```powershell
.\gradlew.bat :app:bundleRelease
```

The bundle is written to `app\build\outputs\bundle\release\app-release.aab`.
