import { useEffect, useState } from "react";
import Navbar from "./components/Navbar.jsx";
import Footer from "./components/Footer.jsx";
import DashboardPage from "./pages/DashboardPage.jsx";
import AnalyzePage from "./pages/AnalyzePage.jsx";
import HistoryPage from "./pages/HistoryPage.jsx";
import AnalyticsPage from "./pages/AnalyticsPage.jsx";
import GuidePage from "./pages/GuidePage.jsx";
import AboutPage from "./pages/AboutPage.jsx";
import { useRoute } from "./lib/router.jsx";

const PAGES = {
  dashboard: DashboardPage,
  analyze: AnalyzePage,
  history: HistoryPage,
  analytics: AnalyticsPage,
  guide: GuidePage,
  about: AboutPage,
};

export default function App() {
  const route = useRoute();
  const Page = PAGES[route] || DashboardPage;
  // Changing the key remounts the page container, replaying the CSS
  // page-enter transition on every navigation.
  const [pageKey, setPageKey] = useState(route);

  useEffect(() => {
    setPageKey(route);
    window.scrollTo(0, 0);
  }, [route]);

  return (
    <div className="shell">
      <a href="#main" className="skip-link">Skip to content</a>
      <Navbar />
      <main id="main" key={pageKey} className="page-enter">
        <Page />
      </main>
      <Footer />
    </div>
  );
}
