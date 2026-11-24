package com.strugglebus.app.activity

import android.util.Log
import com.strugglebus.app.core.MobileWriteService
import com.strugglebus.app.core.OperatorGrantStore
import com.strugglebus.app.core.ProfileStore
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.core.model.HumanMessageKind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

interface HumansPoster {
    /** True when a chat-enabled operator grant is stored, so posts need no device prompt. */
    fun canPost(): Boolean
    suspend fun post(
        requestId: String,
        body: String,
        kind: HumanMessageKind,
        replyTo: Long?,
    ): BusMessage
    fun clearGrant()
}

class HumansRepository(
    private val profileStore: ProfileStore,
    private val writeService: MobileWriteService,
    private val grantStore: OperatorGrantStore,
) : HumansPoster {
    override fun canPost(): Boolean = grantStore.hasGrant() && grantStore.chatSecret() != null

    override suspend fun post(
        requestId: String,
        body: String,
        kind: HumanMessageKind,
        replyTo: Long?,
    ): BusMessage = try {
        val grantSecret = withContext(Dispatchers.IO) {
            checkNotNull(grantStore.chatSecret()) { "Operator access is not set up for chat." }
        }
        writeService.postHumanMessage(
            session = profileStore.loadSession(),
            requestId = requestId,
            body = body,
            kind = kind,
            replyTo = replyTo,
            grantSecret = grantSecret,
        )
    } catch (failure: Exception) {
        if (failure !is CancellationException) Log.w(TAG, "Humans post $requestId failed", failure)
        throw failure
    }

    override fun clearGrant() = grantStore.clear()

    private companion object {
        const val TAG = "StruggleHumans"
    }
}