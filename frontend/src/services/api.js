/**
 * Centralized API client connecting React to FastAPI Backend.
 */
import axios from 'axios';

const API_BASE_URL = 'http://127.0.0.1:8000/api';
const AUTH_BASE_URL = 'http://127.0.0.1:8000/auth';

export const GMAIL_CONNECT_URL = `${AUTH_BASE_URL}/gmail/connect`;

const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json',
    },
    timeout: 25000,
});

// ─── 1. Health & Gmail OAuth ───────────────────────────────────────────────

export const checkBackendHealth = async () => {
    try {
        const response = await api.get('/health');
        return { online: true, data: response.data };
    } catch (error) {
        return { online: false, error: error.message };
    }
};

export const getGmailStatus = async () => {
    const response = await axios.get(`${AUTH_BASE_URL}/gmail/status`);
    return response.data;
};

export const disconnectGmail = async () => {
    const response = await axios.post(`${AUTH_BASE_URL}/gmail/disconnect`);
    return response.data;
};

// ─── 2. Email Inbox & Analysis ──────────────────────────────────────────────

export const getInboxMessages = async (provider = "simulated") => {
    const response = await api.get(`/integration/inbox?provider=${provider}`);
    return response.data;
};

export const analyzeSelectedEmail = async (messageId, provider = "simulated") => {
    const response = await api.post('/integration/analyze-selected', {
        message_id: messageId,
        provider: provider
    });
    return response.data;
};

export const analyzeEmail = async (emailData) => {
    const response = await api.post('/analyze-email', emailData);
    return response.data;
};

export const getAnalysesHistory = async (limit = 20, skip = 0) => {
    const response = await api.get(`/analyses?limit=${limit}&skip=${skip}`);
    return response.data;
};

export const getAnalysisById = async (analysisId) => {
    const response = await api.get(`/analyses/${analysisId}`);
    return response.data;
};

export const deleteAnalysisById = async (analysisId) => {
    const response = await api.delete(`/analyses/${analysisId}`);
    return response.data;
};

// ─── 3. Standalone Artifact Scanners ─────────────────────────────────────────

export const scanUrl = async (url) => {
    const response = await api.post('/scan/url', { url });
    return response.data;
};

export const scanAttachment = async (filename, fileSize = 0, contentType = "application/octet-stream") => {
    const response = await api.post('/scan/attachment', {
        filename,
        file_size_bytes: fileSize,
        content_type: contentType
    });
    return response.data;
};

export const scanHeaders = async (rawHeaders) => {
    const response = await api.post('/scan/headers', {
        raw_headers: rawHeaders
    });
    return response.data;
};

// ─── 4. Threat Investigation Center ──────────────────────────────────────────

export const getInvestigationDossier = async (analysisId) => {
    const response = await api.get(`/investigation/${analysisId}`);
    return response.data;
};

export const generateLiveInvestigation = async (emailPayload) => {
    const response = await api.post('/investigation/live', emailPayload);
    return response.data;
};

// ─── 5. Threat Correlation & Campaigns ──────────────────────────────────────

export const correlateIncidentById = async (analysisId) => {
    const response = await api.get(`/correlation/incident/${analysisId}`);
    return response.data;
};

export const detectAllCampaigns = async () => {
    const response = await api.get('/correlation/campaigns');
    return response.data;
};

export const correlateLiveIncident = async (emailPayload) => {
    const response = await api.post('/correlation/analyze', emailPayload);
    return response.data;
};

// ─── 6. Autonomous Remediation Engine ───────────────────────────────────────

export const executeRemediationById = async (analysisId, dryRun = false) => {
    const response = await api.post(`/remediation/execute/${analysisId}?dry_run=${dryRun}`);
    return response.data;
};

export const executeLiveRemediation = async (payload) => {
    const response = await api.post('/remediation/execute-live', payload);
    return response.data;
};

export const dryRunRemediation = async (payload) => {
    const response = await api.post('/remediation/dry-run', payload);
    return response.data;
};

export const getRemediationAuditLog = async (limit = 50, skip = 0) => {
    const response = await api.get(`/remediation/audit-log?limit=${limit}&skip=${skip}`);
    return response.data;
};

// ─── 7. Remediation Verification Center ──────────────────────────────────────

export const verifyStoredRemediation = async (remediationId) => {
    const response = await api.post(`/verification/verify-remediation/${remediationId}`);
    return response.data;
};

export const verifyLiveRemediation = async (remediationResult) => {
    const response = await api.post('/verification/verify-live', remediationResult);
    return response.data;
};

// ─── 8. 24/7 Watchdog Monitoring ───────────────────────────────────────────

export const getMonitoringStatus = async () => {
    const response = await api.get('/monitoring/status');
    return response.data;
};

export const startMonitoring = async (pollIntervalSeconds = 30, autoRemediate = true, provider = "simulated") => {
    const response = await api.post('/monitoring/start', {
        poll_interval_seconds: pollIntervalSeconds,
        auto_remediate: autoRemediate,
        provider: provider
    });
    return response.data;
};

export const stopMonitoring = async () => {
    const response = await api.post('/monitoring/stop');
    return response.data;
};

export const pollNow = async () => {
    const response = await api.post('/monitoring/poll-now');
    return response.data;
};

export const getMonitoringEvents = async (limit = 25) => {
    const response = await api.get(`/monitoring/events?limit=${limit}`);
    return response.data;
};

export const resetMonitoringCache = async () => {
    const response = await api.post('/monitoring/reset');
    return response.data;
};

// ─── 9. Incident Notifications & Alerts ──────────────────────────────────────

export const getNotifications = async (recipientType = null, unreadOnly = false) => {
    let url = `/notifications?unread_only=${unreadOnly}`;
    if (recipientType) {
        url += `&recipient_type=${recipientType}`;
    }
    const response = await api.get(url);
    return response.data;
};

export const dispatchLiveNotification = async (payload) => {
    const response = await api.post('/notifications/dispatch-live', payload);
    return response.data;
};

export const markNotificationRead = async (notificationId) => {
    const response = await api.patch(`/notifications/${notificationId}/read`);
    return response.data;
};

// ─── 10. Cybersecurity Awareness Training & Quiz ───────────────────────────

export const listTrainingModules = async () => {
    const response = await api.get('/training/modules');
    return response.data;
};

export const getModuleDetail = async (moduleId) => {
    const response = await api.get(`/training/modules/${moduleId}`);
    return response.data;
};

export const getQuizQuestions = async () => {
    const response = await api.get('/training/quiz');
    return response.data;
};

export const submitQuiz = async (answers) => {
    const response = await api.post('/training/quiz/submit', {
        answers: answers
    });
    return response.data;
};

export default api;