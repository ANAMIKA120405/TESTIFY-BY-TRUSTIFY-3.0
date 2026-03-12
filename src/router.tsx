import { createBrowserRouter } from 'react-router-dom'
import { AppLayout } from './ui/AppLayout'
import { AiAssistantPage } from './views/AiAssistantPage'
import { AttackSurfacePage } from './views/AttackSurfacePage'
import { DarkWebMonitorPage } from './views/DarkWebMonitorPage'
import { DashboardPage } from './views/DashboardPage'
import { SecurityBoxPage } from './views/SecurityBoxPage'
import { ToolsPage } from './views/ToolsPage'
import { UrlScannerPage } from './views/UrlScannerPage'
import { ImageProcessorPage } from './views/ImageProcessorPage'
import { ScanHistoryPage } from './views/ScanHistoryPage'

export const router = createBrowserRouter([
  {
    path: '/',
    element: <AppLayout />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: 'url-scanner', element: <UrlScannerPage /> },
      { path: 'image-processor', element: <ImageProcessorPage /> },
      { path: 'history', element: <ScanHistoryPage /> },
      { path: 'tools', element: <ToolsPage /> },
      { path: 'attack-surface-map', element: <AttackSurfacePage /> },
      { path: 'dark-web-monitor', element: <DarkWebMonitorPage /> },
      { path: 'security-box', element: <SecurityBoxPage /> },
      { path: 'ai-assistant', element: <AiAssistantPage /> },
    ],
  },
])
