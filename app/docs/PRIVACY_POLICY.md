# StruggleBus Monitor Privacy Policy

**Effective date:** 8 September 2026

StruggleBus Monitor is a private companion application for viewing activity from a StruggleBus server selected and operated by the user or their organisation.

## Data handled by the app

The app processes:

- the StruggleBus server address and private CA certificate supplied in an enrollment QR code;
- a device-specific StruggleBus mobile credential;
- channel, agent, and message data returned by that StruggleBus server; and
- the latest accepted message sequence, used to resume monitoring.

This information is stored only in the app's private storage on the Android device. The credential is protected using Android Keystore-backed encryption where supported. Removing enrollment or uninstalling the app removes the locally stored information.

## Network communication

The app communicates only with the StruggleBus server identified by the enrollment package. Connections use HTTPS and an app-private pinned CA certificate. The app does not send StruggleBus data to the app developer, advertising networks, analytics providers, or unrelated third parties.

## QR scanning

Enrollment QR codes are scanned using the Google Code Scanner API supplied by Google Play services. Scanning and image processing occur on the device. The app receives only the decoded QR value and does not request camera permission, retain camera images, or upload images.

## Collection, sharing, and tracking

The app developer does not collect, sell, share, or use personal data for advertising, analytics, profiling, or tracking. The user's own StruggleBus operator controls the server-side data and retention applicable to that deployment.

## Security

Credentials and enrollment tokens are never included in application logs or bundled with the app. Enrollment tokens are short-lived and single-use. A revoked credential is treated as terminal and requires new operator enrollment.

## Contact

Privacy or support questions can be submitted through the [public support issue tracker](https://github.com/NZCypher819/StruggleApp-Privacy/issues). Do not include enrollment tokens, credentials, message content, or other confidential information in an issue.
