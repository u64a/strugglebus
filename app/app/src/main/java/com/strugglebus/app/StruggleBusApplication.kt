package com.strugglebus.app

import android.app.Application
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.strugglebus.app.activity.AdminRepository
import com.strugglebus.app.activity.HumansRepository
import com.strugglebus.app.activity.MobileMonitorRepository
import com.strugglebus.app.core.network.MobileApiClient
import com.strugglebus.app.core.network.MobileWriteApiClient
import com.strugglebus.app.core.network.PinnedHttpClientProvider
import com.strugglebus.app.core.security.AndroidCredentialStore
import com.strugglebus.app.core.settings.AppSettings
import com.strugglebus.app.core.security.AndroidOperatorGrantStore
import com.strugglebus.app.core.security.AndroidProfileStore
import com.strugglebus.app.enrollment.EnrollmentPayloadParser

class StruggleBusApplication : Application() {
    lateinit var repository: MobileMonitorRepository
        private set
    lateinit var adminRepository: AdminRepository
        private set
    lateinit var humansRepository: HumansRepository
        private set
    lateinit var settings: AppSettings
        private set

    override fun onCreate() {
        super.onCreate()
        settings = AppSettings(this)
        val moshi = Moshi.Builder()
            .add(KotlinJsonAdapterFactory())
            .build()
        val profileStore = AndroidProfileStore(
            context = this,
            credentialStore = AndroidCredentialStore(this),
        )
        val operatorGrantStore = AndroidOperatorGrantStore(this)
        val clientProvider = PinnedHttpClientProvider()
        repository = MobileMonitorRepository(
            payloadParser = EnrollmentPayloadParser(moshi),
            profileStore = profileStore,
            apiClient = MobileApiClient(moshi, clientProvider = clientProvider),
            operatorGrantStore = operatorGrantStore,
        )
        val writeService = MobileWriteApiClient(moshi, clientProvider)
        adminRepository = AdminRepository(
            profileStore = profileStore,
            monitorRepository = repository,
            writeService = writeService,
            grantStore = operatorGrantStore,
        )
        humansRepository = HumansRepository(
            profileStore = profileStore,
            writeService = writeService,
            grantStore = operatorGrantStore,
        )
    }
}
