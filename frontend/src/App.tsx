import React, { useState } from 'react';
import { Sidebar } from './components/Sidebar';
import { Navbar } from './components/Navbar';
import { DashboardView } from './pages/DashboardView';
import { IngestView } from './pages/IngestView';
import { CasesListView } from './pages/CasesListView';
import { CaseDetailView } from './pages/CaseDetailView';
import { IntelLookupView } from './pages/IntelLookupView';
import { CaseCompareView } from './pages/CaseCompareView';
import { SettingsView } from './pages/SettingsView';

export const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<string>('dashboard');
  const [selectedCaseId, setSelectedCaseId] = useState<number | null>(null);
  const [comparisonCaseIds, setComparisonCaseIds] = useState<number[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleNavigate = (view: string, caseId?: number) => {
    if (caseId) {
      setSelectedCaseId(caseId);
      setCurrentView('case_detail');
    } else {
      setCurrentView(view);
    }
  };

  const handleOpenCaseDetail = (caseId: number) => {
    setSelectedCaseId(caseId);
    setCurrentView('case_detail');
  };

  const handleCompareCases = (caseIds: number[]) => {
    setComparisonCaseIds(caseIds);
    setCurrentView('compare');
  };

  const handleRefresh = () => {
    setIsRefreshing(true);
    // Simple state toggle to re-render active view
    setTimeout(() => {
      setIsRefreshing(false);
    }, 500);
  };

  return (
    <div className="flex h-screen bg-soc-bg text-soc-text font-sans antialiased overflow-hidden">
      {/* Persistent SOC Sidebar */}
      <Sidebar
        currentView={currentView}
        onNavigate={(view) => handleNavigate(view)}
      />

      {/* Main Content Pane */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Navbar
          currentView={currentView}
          onNewInvestigation={() => setCurrentView('ingest')}
          onRefresh={handleRefresh}
          isRefreshing={isRefreshing}
        />

        <main className="flex-1 overflow-y-auto">
          {currentView === 'dashboard' && (
            <DashboardView onNavigate={handleNavigate} />
          )}

          {currentView === 'ingest' && (
            <IngestView onCaseCreated={(caseId) => handleOpenCaseDetail(caseId)} />
          )}

          {currentView === 'cases' && (
            <CasesListView
              onSelectCase={handleOpenCaseDetail}
              onCompareCases={handleCompareCases}
            />
          )}

          {currentView === 'case_detail' && selectedCaseId !== null && (
            <CaseDetailView
              caseId={selectedCaseId}
              onBack={() => setCurrentView('cases')}
            />
          )}

          {currentView === 'intel' && (
            <IntelLookupView />
          )}

          {currentView === 'compare' && (
            <CaseCompareView
              initialCaseIds={comparisonCaseIds}
              onBack={() => setCurrentView('cases')}
              onOpenCase={handleOpenCaseDetail}
            />
          )}

          {currentView === 'settings' && (
            <SettingsView />
          )}
        </main>
      </div>
    </div>
  );
};

export default App;
