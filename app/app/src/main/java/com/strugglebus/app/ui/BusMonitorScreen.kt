package com.strugglebus.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import com.strugglebus.app.core.model.BusMessage
import com.strugglebus.app.core.model.HumanChannel
import com.strugglebus.app.core.settings.AppSettings
import com.strugglebus.app.ui.theme.RetroAmber
import com.strugglebus.app.ui.theme.RetroCream
import com.strugglebus.app.ui.theme.RetroGreen
import com.strugglebus.app.ui.theme.RetroRed
import com.strugglebus.app.ui.theme.RetroTeal
import com.strugglebus.app.ui.theme.RetroTealMuted
import java.time.Instant

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BusMonitorScreen(
    viewModel: BusMonitorViewModel,
    adminViewModel: AdminViewModel,
    humansViewModel: HumansViewModel,
    settings: AppSettings,
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    var selectedPage by rememberSaveable { mutableStateOf(AppPage.MONITOR) }
    var lastSeenHumansSequence by rememberSaveable { mutableStateOf(0L) }
    val enrolled = uiState.connectionState !in setOf(
        ConnectionState.NOT_ENROLLED,
        ConnectionState.ENROLLING,
        ConnectionState.ENROLLMENT_STRANDED,
    )
    LaunchedEffect(uiState.isFrozen) {
        adminViewModel.updateFrozen(uiState.isFrozen)
    }
    LaunchedEffect(enrolled) {
        if (!enrolled && selectedPage != AppPage.SETTINGS) selectedPage = AppPage.MONITOR
    }
    LaunchedEffect(humansViewModel) {
        humansViewModel.posted.collect(viewModel::acceptPostedMessage)
    }
    LaunchedEffect(selectedPage, uiState.messages) {
        if (selectedPage == AppPage.HUMANS) {
            lastSeenHumansSequence = maxOf(
                lastSeenHumansSequence,
                uiState.messages.filter { it.channel == HumanChannel.NAME }
                    .maxOfOrNull(BusMessage::sequence) ?: 0L,
            )
        }
    }
    val humansUnread = HumanChannel.unreadCount(uiState.messages, lastSeenHumansSequence)

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            ConsoleHeader(
                connectionState = uiState.connectionState,
                isFrozen = uiState.isFrozen,
                page = selectedPage,
                enrolled = enrolled,
                humansUnread = humansUnread,
                onSwitchPage = { selectedPage = it },
            )
        },
    ) { padding ->
        if (selectedPage == AppPage.SETTINGS) {
            SettingsScreen(
                settings = settings,
                enrolled = enrolled,
                onRemoveEnrollment = {
                    selectedPage = AppPage.MONITOR
                    viewModel.removeEnrollment()
                },
                modifier = Modifier.padding(padding),
            )
        } else if (!enrolled) {
            EnrollmentScreen(
                state = uiState,
                onEnroll = viewModel::enroll,
                modifier = Modifier.padding(padding),
            )
        } else if (selectedPage == AppPage.ADMIN) {
            AdminScreen(
                viewModel = adminViewModel,
                onDeviceRevoked = {
                    selectedPage = AppPage.MONITOR
                    viewModel.removeEnrollment()
                },
                modifier = Modifier.padding(padding),
            )
        } else if (selectedPage == AppPage.HUMANS) {
            HumansScreen(
                viewModel = humansViewModel,
                messages = uiState.messages,
                agents = uiState.agents,
                modifier = Modifier.padding(padding),
            )
        } else {
            MonitorScreen(
                state = uiState,
                onChannelSelected = viewModel::selectChannel,
                onRecover = viewModel::recover,
                onQueryChange = viewModel::setQuery,
                onAgentSelected = viewModel::toggleAgentFilter,
                onSearchBus = viewModel::searchBus,
                onClearSearch = viewModel::clearSearch,
                onLoadOlder = viewModel::loadOlder,
                modifier = Modifier.padding(padding),
            )
        }
    }
}

private enum class AppPage(val label: String) {
    MONITOR("MONITOR"),
    HUMANS("HUMANS"),
    ADMIN("ADMIN"),
    SETTINGS("SETTINGS"),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ConsoleHeader(
    connectionState: ConnectionState,
    isFrozen: Boolean,
    page: AppPage,
    enrolled: Boolean,
    humansUnread: Int,
    onSwitchPage: (AppPage) -> Unit,
) {
  Column {
    TopAppBar(
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = MaterialTheme.colorScheme.background,
            titleContentColor = RetroCream,
        ),
        title = {
            Column(verticalArrangement = Arrangement.spacedBy(1.dp)) {
                Text(
                    "STRUGGLEBUS // ${page.label}",
                    style = MaterialTheme.typography.titleMedium,
                    color = RetroAmber,
                )
                Text(
                    "LAN OPERATOR CONSOLE",
                    style = MaterialTheme.typography.bodySmall,
                    color = RetroTealMuted,
                )
            }
        },
        actions = {
            ConnectionBadge(connectionState, isFrozen)
            Spacer(Modifier.width(16.dp))
        },
    )
    Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp)) {
        AppPage.entries.forEach { target ->
            val selected = target == page
            val available = enrolled || target == AppPage.MONITOR || target == AppPage.SETTINGS
            val unread = target == AppPage.HUMANS && humansUnread > 0 && !selected
            Column(
                modifier = Modifier
                    .weight(1f)
                    .clickable(enabled = available && !selected, role = Role.Tab) { onSwitchPage(target) }
                    .padding(top = 8.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = if (unread) "${target.label} ($humansUnread)" else target.label,
                    style = MaterialTheme.typography.labelMedium,
                    maxLines = 1,
                    color = when {
                        selected || unread -> RetroAmber
                        available -> RetroTeal
                        else -> MaterialTheme.colorScheme.outlineVariant
                    },
                )
                Box(
                    Modifier
                        .fillMaxWidth()
                        .height(2.dp)
                        .background(if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant),
                )
            }
        }
    }
  }
}

@Composable
private fun ConnectionBadge(connectionState: ConnectionState, isFrozen: Boolean) {
    val healthy = connectionState == ConnectionState.CONNECTED && !isFrozen
    val color = if (isFrozen) {
        RetroRed
    } else {
        when (connectionState) {
            ConnectionState.CONNECTED -> RetroGreen
            ConnectionState.FROZEN,
            ConnectionState.REVOKED,
            ConnectionState.STOPPED,
            ConnectionState.ENROLLMENT_STRANDED -> RetroRed
            else -> RetroAmber
        }
    }
    val label = if (isFrozen) {
        "FROZEN"
    } else {
        when (connectionState) {
            ConnectionState.CONNECTED -> "LIVE"
            ConnectionState.RECONNECTING -> "RETRY"
            ConnectionState.LOADING_SNAPSHOT,
            ConnectionState.CONNECTING,
            ConnectionState.ENROLLING -> "SYNC"
            ConnectionState.NOT_ENROLLED -> "OFFLINE"
            ConnectionState.ENROLLMENT_STRANDED -> "STRANDED"
            else -> connectionState.name
        }
    }
    Row(
        modifier = Modifier
            .border(1.dp, color, MaterialTheme.shapes.extraSmall)
            .padding(horizontal = 8.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Box(
            Modifier
                .size(7.dp)
                .background(color, MaterialTheme.shapes.extraSmall),
        )
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = if (healthy) RetroGreen else color,
        )
    }
}

@Composable
private fun EnrollmentScreen(
    state: BusMonitorUiState,
    onEnroll: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var payload by remember { mutableStateOf("") }
    var scanError by remember { mutableStateOf<String?>(null) }
    var manualEntry by rememberSaveable { mutableStateOf(false) }
    val enrolling = state.connectionState == ConnectionState.ENROLLING
    val context = LocalContext.current
    val scanner = remember(context) {
        val options = GmsBarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .enableAutoZoom()
            .build()
        GmsBarcodeScanning.getClient(context, options)
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("One-time enrollment", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Scan the one-time operator code. The embedded CA is verified before the enrollment token is sent.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Button(
            enabled = !enrolling,
            onClick = {
                scanError = null
                scanner.startScan()
                    .addOnSuccessListener { barcode ->
                        val rawPayload = barcode.rawValue
                        if (rawPayload.isNullOrBlank()) {
                            scanError = "The QR code did not contain an enrollment payload."
                        } else {
                            onEnroll(rawPayload)
                        }
                    }
                    .addOnFailureListener {
                        scanError = "Unable to scan the enrollment code."
                    }
            },
        ) {
            if (enrolling) {
                CircularProgressIndicator(
                    modifier = Modifier.padding(end = 8.dp),
                    strokeWidth = 2.dp,
                )
            }
            Text(if (enrolling) "Enrolling" else "Scan enrollment QR")
        }
        TextButton(
            enabled = !enrolling,
            onClick = {
                scanError = null
                if (manualEntry) payload = ""
                manualEntry = !manualEntry
            },
        ) {
            Text(
                if (manualEntry) "CANCEL MANUAL ENTRY" else "PASTE ENROLLMENT CODE INSTEAD",
                style = MaterialTheme.typography.labelMedium,
                color = RetroTealMuted,
            )
        }
        scanError?.let { StatusPanel(it, error = true) }
        state.detail?.let { StatusPanel(it, error = true) }
        if (manualEntry) {
            Text(
                "Paste the operator enrollment package shown beneath the QR code. It is single-use and expires within minutes.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = payload,
                onValueChange = { payload = it },
                label = { Text("Enrollment JSON") },
                visualTransformation = PasswordVisualTransformation(),
                minLines = 3,
                enabled = !enrolling,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                enabled = !enrolling && payload.isNotBlank(),
                onClick = {
                    val submittedPayload = payload
                    payload = ""
                    onEnroll(submittedPayload)
                },
            ) {
                Text("Verify pasted payload")
            }
        }
    }
}

private val expandedSequencesSaver: Saver<Set<Long>, LongArray> = Saver(
    save = { it.toLongArray() },
    restore = { it.toSet() },
)

@Composable
private fun MonitorScreen(
    state: BusMonitorUiState,
    onChannelSelected: (String?) -> Unit,
    onRecover: () -> Unit,
    onQueryChange: (String) -> Unit,
    onAgentSelected: (String) -> Unit,
    onSearchBus: () -> Unit,
    onClearSearch: () -> Unit,
    onLoadOlder: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val visibleMessages = remember(state.messages, state.history, state.searchResults, state.query, state.selectedChannel) {
        MonitorLogic.visibleMessages(state)
    }
    val query = remember(state.query) { FeedLogic.parseQuery(state.query) }
    val showingSearch = state.searchResults != null
    val sortedAgents = remember(state.agents) { FeedLogic.sortAgents(state.agents) }
    val now = remember(state.agents, state.messages) { Instant.now() }
    var expandedSequences by rememberSaveable(stateSaver = expandedSequencesSaver) {
        mutableStateOf(emptySet<Long>())
    }
    val abnormalState = state.connectionState !in setOf(
        ConnectionState.CONNECTED,
        ConnectionState.LOADING_SNAPSHOT,
        ConnectionState.CONNECTING,
    )

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (state.isFrozen) {
            item {
                StatusPanel(
                    message = "FROZEN — live monitoring and existing operator controls remain available; enrollment and new grant setup are blocked.",
                    error = true,
                )
            }
        }
        if (abnormalState) {
            item {
                StatusPanel(
                    message = connectionDescription(state.connectionState),
                    error = state.connectionState in setOf(
                        ConnectionState.FROZEN,
                        ConnectionState.REVOKED,
                        ConnectionState.STOPPED,
                    ),
                    actionLabel = if (state.connectionState in setOf(
                            ConnectionState.FROZEN,
                            ConnectionState.STOPPED,
                        )
                    ) "RETRY" else null,
                    onAction = onRecover,
                )
            }
        }
        state.detail?.let { detail ->
            item { StatusPanel(detail, error = true) }
        }
        item {
            OutlinedTextField(
                value = state.query,
                onValueChange = onQueryChange,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                singleLine = true,
                placeholder = { Text("Filter messages, from:agent, in:channel") },
                trailingIcon = {
                    if (state.query.isNotEmpty()) {
                        TextButton(onClick = { onQueryChange("") }) {
                            Text("CLEAR", style = MaterialTheme.typography.labelMedium)
                        }
                    }
                },
            )
        }
        if (query.text.isNotBlank() || showingSearch || state.historyNote != null) {
            item {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        text = state.historyNote ?: if (showingSearch) {
                            "Showing matches from the whole bus."
                        } else {
                            "Filtering the messages on this phone."
                        },
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodySmall,
                        color = RetroTealMuted,
                    )
                    if (showingSearch) {
                        TextButton(onClick = onClearSearch) {
                            Text("BACK TO LIVE", style = MaterialTheme.typography.labelMedium)
                        }
                    } else if (query.text.isNotBlank()) {
                        TextButton(enabled = !state.historyBusy, onClick = onSearchBus) {
                            Text(
                                if (state.historyBusy) "SEARCHING" else "SEARCH WHOLE BUS",
                                style = MaterialTheme.typography.labelMedium,
                            )
                        }
                    }
                }
            }
        }
        if (sortedAgents.isNotEmpty()) {
            item { Box(Modifier.padding(horizontal = 16.dp)) { SectionLabel("AGENTS") } }
            item {
                LazyRow(
                    modifier = Modifier.fillMaxWidth(),
                    contentPadding = PaddingValues(horizontal = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(sortedAgents, key = { it.id }) { agent ->
                        val seen = FeedLogic.lastSeen(agent)
                        AgentChip(
                            name = agent.name,
                            presence = FeedLogic.presence(seen, now),
                            label = FeedLogic.presenceLabel(seen, now),
                            selected = query.agent.equals(agent.name, ignoreCase = true),
                            onClick = { onAgentSelected(agent.name) },
                        )
                    }
                }
            }
        }
        item { Box(Modifier.padding(start = 16.dp, end = 16.dp, top = 6.dp)) { SectionLabel("CHANNELS") } }
        if (state.channels.isNotEmpty()) {
            item {
                LazyRow(
                    modifier = Modifier.fillMaxWidth(),
                    contentPadding = PaddingValues(horizontal = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    item {
                        ChannelChip(
                            label = "ALL",
                            selected = state.selectedChannel == null,
                            onClick = { onChannelSelected(null) },
                        )
                    }
                    items(state.channels, key = { it.id }) { channel ->
                        ChannelChip(
                            label = "#${channel.name.uppercase()}",
                            selected = state.selectedChannel == channel.name,
                            onClick = { onChannelSelected(channel.name) },
                        )
                    }
                }
            }
        }
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 16.dp, end = 16.dp, top = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                SectionLabel(if (showingSearch) "BUS SEARCH" else "LIVE FEED")
                Text(
                    "${visibleMessages.size} EVENTS",
                    style = MaterialTheme.typography.bodySmall,
                    color = RetroTealMuted,
                )
            }
        }
        if (visibleMessages.isEmpty()) {
            item {
                Surface(
                    color = MaterialTheme.colorScheme.surface,
                    shape = MaterialTheme.shapes.medium,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp)
                        .border(1.dp, MaterialTheme.colorScheme.outlineVariant, MaterialTheme.shapes.medium),
                ) {
                    Text(
                        if (query.isEmpty && state.selectedChannel == null) "NO ACTIVITY YET" else "NOTHING MATCHES",
                        modifier = Modifier.padding(18.dp),
                        style = MaterialTheme.typography.labelMedium,
                        color = RetroTealMuted,
                    )
                }
            }
        } else {
            items(visibleMessages, key = BusMessage::sequence) { message ->
                MessageCard(
                    message = message,
                    highlight = query.text,
                    expanded = message.sequence in expandedSequences,
                    onToggle = {
                        expandedSequences = if (message.sequence in expandedSequences) {
                            expandedSequences - message.sequence
                        } else {
                            expandedSequences + message.sequence
                        }
                    },
                )
            }
        }
        if (MonitorLogic.historyFilter(state) != null) {
            item {
                Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp), horizontalArrangement = Arrangement.Center) {
                    OutlinedButton(enabled = !state.historyBusy, onClick = onLoadOlder) {
                        Text(if (state.historyBusy) "LOADING" else "LOAD OLDER MESSAGES")
                    }
                }
            }
        }
    }
}

@Composable
private fun AgentChip(
    name: String,
    presence: AgentPresence,
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .background(
                if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface,
                MaterialTheme.shapes.small,
            )
            .border(
                1.dp,
                if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant,
                MaterialTheme.shapes.small,
            )
            .clickable(onClickLabel = "Show messages from $name", onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        PresenceDot(presence)
        Column {
            Text(name, style = MaterialTheme.typography.labelMedium, color = RetroCream)
            Text(label, style = MaterialTheme.typography.bodySmall, color = RetroTealMuted)
        }
    }
}

private fun connectionDescription(state: ConnectionState): String = when (state) {
    ConnectionState.LOADING_SNAPSHOT -> "Loading cold-start snapshot"
    ConnectionState.CONNECTING -> "Opening activity stream"
    ConnectionState.CONNECTED -> "Connected"
    ConnectionState.RECONNECTING -> "Reconnecting from the last accepted sequence"
    ConnectionState.FROZEN -> "Agent access frozen"
    ConnectionState.REVOKED -> "Mobile credential inactive"
    ConnectionState.STOPPED -> "Activity stream stopped"
    else -> state.name.replace('_', ' ').lowercase()
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelLarge,
        color = RetroAmber,
    )
}

@Composable
private fun ChannelChip(label: String, selected: Boolean, onClick: () -> Unit) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label, style = MaterialTheme.typography.labelMedium) },
        shape = MaterialTheme.shapes.small,
        colors = FilterChipDefaults.filterChipColors(
            containerColor = MaterialTheme.colorScheme.surface,
            labelColor = RetroTeal,
            selectedContainerColor = MaterialTheme.colorScheme.primary,
            selectedLabelColor = MaterialTheme.colorScheme.onPrimary,
        ),
        border = FilterChipDefaults.filterChipBorder(
            enabled = true,
            selected = selected,
            borderColor = MaterialTheme.colorScheme.outline,
            selectedBorderColor = MaterialTheme.colorScheme.primary,
        ),
    )
}

@Composable
private fun StatusPanel(
    message: String,
    error: Boolean,
    actionLabel: String? = null,
    onAction: () -> Unit = {},
) {
    val color = if (error) RetroRed else RetroAmber
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
            .background(MaterialTheme.colorScheme.surface, MaterialTheme.shapes.medium)
            .border(1.dp, color, MaterialTheme.shapes.medium)
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("!", style = MaterialTheme.typography.titleMedium, color = color)
        Text(
            text = message,
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
        )
        actionLabel?.let {
            TextButton(onClick = onAction) {
                Text(it, style = MaterialTheme.typography.labelMedium, color = color)
            }
        }
    }
}

@Composable
private fun MessageCard(
    message: BusMessage,
    highlight: String,
    expanded: Boolean,
    onToggle: () -> Unit,
) {
    val summary = remember(message.body) { MessagePreview.summarise(message.body) }
    val interactionModifier = if (summary.expandable) {
        Modifier.clickable(
            onClickLabel = if (expanded) "Collapse message" else "Show full message",
            onClick = onToggle,
        )
    } else {
        Modifier
    }

    Surface(
        color = MaterialTheme.colorScheme.surface,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, MaterialTheme.shapes.medium)
            .then(interactionModifier),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 13.dp, vertical = 11.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    "#${message.channel.uppercase()}",
                    style = MaterialTheme.typography.labelLarge,
                    color = RetroAmber,
                )
                Text(
                    message.kind.uppercase(),
                    style = MaterialTheme.typography.bodySmall,
                    color = RetroTeal,
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    message.agentName,
                    style = MaterialTheme.typography.labelMedium,
                    color = RetroTeal,
                )
                Text(
                    "SEQ ${message.sequence}",
                    style = MaterialTheme.typography.bodySmall,
                    color = RetroTealMuted,
                )
            }
            Box(
                Modifier
                    .fillMaxWidth()
                    .height(1.dp)
                    .background(MaterialTheme.colorScheme.outlineVariant),
            )
            Text(
                text = richText(if (expanded) message.body else summary.preview, highlight),
                maxLines = if (expanded) Int.MAX_VALUE else 3,
                overflow = TextOverflow.Ellipsis,
                style = MaterialTheme.typography.bodyMedium,
                color = RetroCream,
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    formatActivityTime(message.createdAt),
                    style = MaterialTheme.typography.bodySmall,
                    color = RetroTealMuted,
                )
                if (summary.expandable) {
                    Text(
                        if (expanded) "[-] COLLAPSE" else "[+] READ ${summary.characterCount}",
                        style = MaterialTheme.typography.labelMedium,
                        color = RetroAmber,
                    )
                }
            }
        }
    }
}
