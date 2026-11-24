# Moshi uses Kotlin reflection for these strict wire adapters.
-keep class com.strugglebus.app.core.network.** { *; }
-keep class com.strugglebus.app.enrollment.EnrollmentPayloadWire { *; }
-keepattributes RuntimeVisibleAnnotations,RuntimeInvisibleAnnotations,AnnotationDefault,Signature,InnerClasses,EnclosingMethod
