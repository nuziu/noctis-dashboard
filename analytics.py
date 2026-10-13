import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import yfinance as yf
from sklearn.ensemble import RandomForestRegressor
from datetime import datetime
from pathlib import Path
import json as json_storage
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import json
import re
import html
import xml.etree.ElementTree as ET
from urllib.parse import quote_plus, urlparse, parse_qs

st.set_page_config(page_title="NOCTIS Intelligence", page_icon="🌌", layout="wide")

with st.sidebar:
    st.title("✦ NOCTIS")
    st.caption("MULTI-MARKET INTELLIGENCE")
    st.divider()
    market_space = st.selectbox(
        "MARKET SPACE",
        ["📈 Trading & Crypto", "⚡ Alternative Markets"],
        key="noctis_market_space",
    )
    if market_space == "📈 Trading & Crypto":
        page = st.radio(
            "STOCKS & CRYPTO",
            ["Trading Terminal", "Market Volume", "Stock Research", "Trader Forums", "My Watchlist", "Stocks for Beginners", "Market Videos & Live"],
            key="noctis_stock_navigation",
        )
        st.caption("Market research · delayed daily quotes")
    else:
        st.markdown("<div class='alt-sidebar-tag'>✦ COLLECTIBLES / SPORTS / GAMING</div>", unsafe_allow_html=True)
        page = st.radio(
            "ALTERNATIVE MARKETS",
            ["Alternative Market Overview", "Pokémon Card Market", "Pokémon Community", "Sportsbook & Prediction Research", "Sports & Prediction Forums", "Gambling Site Research", "Gambling Research Forums"],
            key="noctis_alt_navigation",
        )
        st.caption("Public information · no wagering")
    st.divider()
    st.caption("LOCAL TEST  •  INFORMATION ONLY")

@st.cache_data(ttl=900, show_spinner=False)
def fetch_market_history(ticker):
    data = yf.Ticker(ticker).history(period="2y", interval="1d", auto_adjust=True)
    if data.empty:
        raise ValueError("No market data returned for this symbol.")
    data = data.dropna(subset=["Open", "High", "Low", "Close"])
    return data


def evaluate_forecast(data):
    # Train only on earlier observations; test on later observations.
    close = data["Close"].astype(float).reset_index(drop=True)
    returns = close.pct_change()
    features = pd.DataFrame({
        "return_1": returns,
        "return_2": returns.shift(1),
        "return_3": returns.shift(2),
        "mean_5": returns.rolling(5).mean(),
        "mean_20": returns.rolling(20).mean(),
        "volatility_10": returns.rolling(10).std(),
    })
    # Target is next trading day's percentage return.
    target = returns.shift(-1).rename("target")
    dataset = features.join(target).dropna()
    if len(dataset) < 100:
        return None
    x = dataset.drop(columns=["target"])
    y = dataset["target"]
    split = int(len(dataset) * 0.8)
    model = RandomForestRegressor(n_estimators=80, max_depth=5, min_samples_leaf=5, random_state=42, n_jobs=1)
    model.fit(x.iloc[:split], y.iloc[:split])
    predictions = model.predict(x.iloc[split:])
    actual = y.iloc[split:].to_numpy()
    mae = float(abs(predictions - actual).mean() * 100)
    directional = float(((predictions > 0) == (actual > 0)).mean() * 100)
    # Latest features are not part of the labeled dataset because tomorrow is unknown.
    newest = features.dropna().iloc[[-1]]
    next_prediction = float(model.predict(newest)[0] * 100)
    comparison = pd.DataFrame({
        "Actual next-day change (%)": actual * 100,
        "Predicted next-day change (%)": predictions * 100,
    })
    return mae, directional, next_prediction, comparison


def trader_community(ticker, company):
    st.subheader("STOCK DISCUSSION HUB")
    st.caption("Jump directly to conversations and trading ideas for your selected asset. External websites open in a new tab.")

    selected = st.text_input("Stock or crypto ticker", value=ticker, key=f"discussion_symbol_{ticker}").strip().upper()
    if not selected:
        st.info("Enter a ticker symbol to find discussions.")
        return
    if not re.fullmatch(r"[A-Z0-9.^=-]{1,18}", selected):
        st.warning("Use a ticker symbol such as NVDA, AAPL, TSLA, SPY, or BTC-USD.")
        return

    # Match the naming conventions of each destination.
    stocktwits_symbol = "BTC.X" if selected in ("BTC", "BTC-USD") else selected
    reddit_term = "BTC" if selected == "BTC-USD" else selected
    tv_exchange = {
        "AAPL": "NASDAQ", "MSFT": "NASDAQ", "NVDA": "NASDAQ", "TSLA": "NASDAQ",
        "SPY": "AMEX", "BTC": "BITSTAMP", "BTC-USD": "BITSTAMP",
    }.get(selected)
    tv_symbol = "BTCUSD" if selected in ("BTC", "BTC-USD") else selected

    st.markdown(f"### Discussions for ${selected}")
    st.caption("These links lead to the platforms themselves. They are not scraped posts or verified trading recommendations.")
    left, right = st.columns(2)
    with left:
        with st.container(border=True):
            st.markdown("#### Stocktwits")
            st.write("Trader posts and market sentiment for this symbol.")
            st.link_button("Open stock discussion ↗", f"https://stocktwits.com/symbol/{stocktwits_symbol}", use_container_width=True)
        with st.container(border=True):
            st.markdown("#### Reddit")
            st.write("Find posts mentioning this ticker across Reddit communities.")
            st.link_button("Search Reddit discussions ↗", "https://www.reddit.com/search/?" + urlencode({"q": reddit_term + " stock", "sort": "new"}), use_container_width=True)
            st.link_button("Search r/stocks ↗", "https://www.reddit.com/r/stocks/search/?" + urlencode({"q": reddit_term, "restrict_sr": "1", "sort": "new"}), use_container_width=True)
    with right:
        with st.container(border=True):
            st.markdown("#### TradingView")
            st.write("Chart-based ideas and analysis posted by traders.")
            if tv_exchange:
                tv_url = f"https://www.tradingview.com/symbols/{tv_exchange}-{tv_symbol}/ideas/"
                st.link_button("Open trading ideas ↗", tv_url, use_container_width=True)
            else:
                st.link_button("Find ticker on TradingView ↗", "https://www.tradingview.com/search/?" + urlencode({"query": tv_symbol}), use_container_width=True)
        with st.container(border=True):
            st.markdown("#### r/wallstreetbets")
            st.write("Search speculative trades, options talk, and ticker discussions.")
            st.link_button("Search r/wallstreetbets ↗", "https://www.reddit.com/r/wallstreetbets/search/?" + urlencode({"q": reddit_term, "restrict_sr": "1", "sort": "new"}), use_container_width=True)

    st.info("Posts are opinions, not verified forecasts. Some platforms may require you to sign in to view or participate.")


# Pins are saved only on this computer, next to analytics.py.
PINS_FILE = Path(__file__).resolve().with_name("noctis_watchlist.json")


def load_pins():
    try:
        values = json_storage.loads(PINS_FILE.read_text(encoding="utf-8"))
        if isinstance(values, list):
            return [v for v in values if isinstance(v, str) and re.fullmatch(r"[A-Z0-9.^=\-]{1,20}", v)]
    except (OSError, ValueError, TypeError):
        pass
    return []


def save_pins(values):
    try:
        PINS_FILE.write_text(json_storage.dumps(list(dict.fromkeys(values)), indent=2), encoding="utf-8")
    except OSError as exc:
        st.error(f"Couldn't save the watchlist locally: {exc}")


MARKET_GROUPS = {
    "Technology & AI": "AAPL MSFT NVDA AMD GOOGL GOOG AMZN META AVGO ORCL CRM ADBE INTC MU QCOM TXN AMAT LRCX KLAC SNOW PLTR NET CRWD PANW NOW IBM DELL HPE SHOP UBER ABNB SPOT NFLX RBLX DDOG MDB ARM SMCI".split(),
    "Finance & Payments": "JPM BAC WFC C GS MS CITI V MA AXP PYPL SQ COIN HOOD SCHW BLK BX KKR USB PNC TFC SOFI".split(),
    "Consumer & Retail": "TSLA WMT COST TGT HD LOW NKE SBUX MCD CMG KO PEP PG ULTA LULU DIS ROKU F GM RIVN LCID BABA PDD".split(),
    "Healthcare & Pharma": "LLY UNH JNJ ABBV MRK PFE AMGN GILD ISRG TMO DHR ABT BMY CVS CI HUM NVO REGN VRTX".split(),
    "Energy & Industry": "XOM CVX COP OXY SLB EOG VLO CAT DE GE GEHC BA LMT RTX NOC UPS FDX UNP HON MMM".split(),
    "ETFs & Indices": "SPY QQQ VOO VTI DIA IWM XLK XLF XLE XLV XLY XLI XLP XLU XLB SMH SOXX ARKK SCHD VIG VYM GLD SLV TLT HYG EEM EFA".split(),
    "Crypto": "BTC-USD ETH-USD SOL-USD XRP-USD ADA-USD DOGE-USD AVAX-USD LINK-USD LTC-USD BCH-USD".split(),
}

@st.cache_data(ttl=900, show_spinner=False)
def market_board_quotes(symbols):
    # Fetch only the visible page, not the entire market on each rerun.
    out = []
    for sym in symbols:
        try:
            hist = yf.Ticker(sym).history(period="5d", interval="1d", auto_adjust=True)
            if len(hist) < 2:
                continue
            last = float(hist["Close"].iloc[-1]); prev = float(hist["Close"].iloc[-2])
            out.append({"Symbol": sym, "Last ($)": round(last, 2), "Change (%)": round((last / prev - 1) * 100, 2), "Volume": int(hist["Volume"].iloc[-1]) if "Volume" in hist else 0, "As of": str(hist.index[-1].date())})
        except Exception:
            continue
    return out


def market_overview():
    st.markdown('<div class="terminal-hero"><div class="terminal-kicker">✦ NOCTIS / MARKET RADAR</div><div class="terminal-title">THE MARKET <span>AT A GLANCE</span></div><div class="terminal-sub">Explore a broad directory of publicly quoted assets · Pin favorites · Open deep research</div></div>', unsafe_allow_html=True)
    all_symbols = list(dict.fromkeys(sym for group in MARKET_GROUPS.values() for sym in group))
    a, b, c = st.columns(3)
    a.metric("TRACKED SYMBOL DIRECTORY", len(all_symbols))
    b.metric("MARKET SECTORS", len(MARKET_GROUPS))
    c.metric("MY PINNED STOCKS", len(load_pins()))
    st.caption("This is a curated discovery directory, not a complete exchange listing. Prices are latest available daily candles, not live quotes.")
    group = st.selectbox("EXPLORE MARKET CATEGORY", list(MARKET_GROUPS), key="market_category")
    symbols = MARKET_GROUPS[group]
    page_count = (len(symbols) + 11) // 12
    page_num = st.number_input("MARKET PAGE", min_value=1, max_value=page_count, value=1, step=1, key=f"market_page_{group}")
    visible = symbols[(page_num - 1) * 12: page_num * 12]
    st.markdown(f"#### ✦ {group.upper()} · {len(symbols)} SYMBOLS")
    with st.spinner("Loading market board..."):
        rows = market_board_quotes(tuple(visible))
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.warning("Quotes are temporarily unavailable. You can still explore and pin symbols below.")
    pinned = load_pins()
    st.markdown("#### EXPLORE & PIN")
    for sym in visible:
        left, middle, right = st.columns([3, 1, 1], vertical_alignment="center")
        left.markdown(f"**{sym}**")
        if middle.button("★ Pinned" if sym in pinned else "☆ Pin", key=f"board_pin_{sym}", disabled=sym in pinned, use_container_width=True):
            save_pins(pinned + [sym]); st.rerun()
        if right.button("Analyze ↗", key=f"board_open_{sym}", use_container_width=True):
            st.session_state.terminal_research_symbol = sym
            st.rerun()
    if st.session_state.get("terminal_research_symbol"):
        st.divider()
        with st.expander(f"✦ FULL MARKET PROFILE / {st.session_state.terminal_research_symbol}", expanded=True):
            asset_detail(st.session_state.terminal_research_symbol)
    st.info("Want a company not shown? Open Stock Research in the sidebar to search by company name or ticker.")


@st.cache_data(ttl=3600, show_spinner=False)
def search_assets(query):
    """Best-effort Yahoo Finance public symbol lookup, with a local fallback."""
    catalog = {
        "AAPL": "Apple", "MSFT": "Microsoft", "NVDA": "NVIDIA", "GOOGL": "Alphabet Google",
        "AMZN": "Amazon", "META": "Meta Platforms", "TSLA": "Tesla", "AMD": "Advanced Micro Devices",
        "INTC": "Intel", "NFLX": "Netflix", "PLTR": "Palantir", "COIN": "Coinbase",
        "HOOD": "Robinhood", "JPM": "JPMorgan Chase", "BAC": "Bank of America", "WMT": "Walmart",
        "COST": "Costco", "DIS": "Walt Disney", "KO": "Coca-Cola", "PEP": "PepsiCo",
        "NKE": "Nike", "BA": "Boeing", "F": "Ford", "GM": "General Motors",
        "V": "Visa", "MA": "Mastercard", "PYPL": "PayPal", "UBER": "Uber",
        "SPY": "S&P 500 ETF", "QQQ": "Nasdaq 100 ETF", "VOO": "Vanguard S&P 500 ETF",
        "VTI": "Vanguard Total Market ETF", "IWM": "Russell 2000 ETF", "DIA": "Dow Jones ETF",
        "SCHD": "Schwab Dividend ETF", "GLD": "Gold ETF", "SLV": "Silver ETF",
        "BTC-USD": "Bitcoin", "ETH-USD": "Ethereum", "SOL-USD": "Solana",
    }
    q = query.strip().lower()
    matches = [(k, v) for k, v in catalog.items() if q in k.lower() or q in v.lower()]
    if len(q) >= 2:
        try:
            endpoint = "https://query1.finance.yahoo.com/v1/finance/search?" + urlencode({"q": query, "quotesCount": 20, "newsCount": 0})
            req = Request(endpoint, headers={"User-Agent": "Mozilla/5.0"})
            with urlopen(req, timeout=5) as response:
                payload = json.loads(response.read(150000))
            for item in payload.get("quotes", []):
                symbol = str(item.get("symbol", "")).upper()
                label = str(item.get("shortname") or item.get("longname") or symbol)
                if re.fullmatch(r"[A-Z0-9.^=\-]{1,20}", symbol) and (symbol, label) not in matches:
                    matches.append((symbol, label))
        except Exception:
            pass
    unique = {}
    for symbol, label in matches:
        unique.setdefault(symbol, label)
    return list(unique.items())[:35]


def asset_detail(sym):
    try:
        hist = fetch_market_history(sym)
    except Exception as exc:
        st.warning(f"Market history unavailable for {sym}: {str(exc)[:100]}")
        return
    close = hist["Close"].astype(float)
    last = float(close.iloc[-1])
    previous = float(close.iloc[-2]) if len(close) > 1 else last
    st.markdown(f"### {sym} / ASSET INTELLIGENCE")
    st.caption(f"Last available daily candle: {hist.index[-1].strftime('%Y-%m-%d')} • Delayed data, not a live quote")
    a, b, c, d = st.columns(4)
    a.metric("LAST CLOSE", f"${last:,.2f}", f"{(last / previous - 1) * 100:+.2f}%")
    b.metric("52-WEEK HIGH", f"${hist['High'].tail(252).max():,.2f}")
    c.metric("52-WEEK LOW", f"${hist['Low'].tail(252).min():,.2f}")
    d.metric("30-DAY CHANGE", f"{(last / float(close.iloc[-min(31,len(close))]) - 1) * 100:+.2f}%")
    fig = go.Figure(go.Candlestick(x=hist.tail(130).index, open=hist['Open'].tail(130), high=hist['High'].tail(130), low=hist['Low'].tail(130), close=hist['Close'].tail(130), increasing_line_color="#c68cff", decreasing_line_color="#777777", increasing_fillcolor="#b36dff", decreasing_fillcolor="#4b4b4b"))
    fig.update_layout(height=420, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#eeeeee"), xaxis_rangeslider_visible=False, xaxis=dict(showgrid=False), yaxis=dict(gridcolor="#333333"), margin=dict(l=5,r=5,t=10,b=10))
    st.plotly_chart(fig, use_container_width=True)
    c1, c2, c3 = st.columns(3)
    c1.metric("20-SESSION AVERAGE", f"${close.tail(20).mean():,.2f}")
    c2.metric("50-SESSION AVERAGE", f"${close.tail(50).mean():,.2f}")
    c3.metric("LATEST VOLUME", f"{int(hist['Volume'].iloc[-1]):,}" if 'Volume' in hist else "N/A")
    st.caption("Statistics are computed from available daily historical candles. Adjusted prices may differ from exchange quotes.")


def watchlist_page():
    st.markdown('<div class="noctis-watch-hero"><div class="watch-eyebrow">✦ PERSONAL MARKET COMMAND CENTER</div><div class="watch-title">MY WATCHLIST <span>✦</span></div><div class="watch-sub">Your personal stock collection · Detailed profiles · Neon market intelligence</div></div>', unsafe_allow_html=True)
    pinned = load_pins()
    x, y = st.columns([3, 1])
    x.metric("PINNED ASSETS", len(pinned))
    y.metric("RESEARCH MODE", "ACTIVE")
    st.caption("Your pinned assets live here. Discover and pin more stocks from Trading Terminal → Market Overview or Stock Search & Charts.")
    st.divider()
    st.markdown("### ★ YOUR PINNED MARKETS")
    if not pinned:
        st.info("Your watchlist is empty. Open Trading Terminal, explore the market, and pin stocks you want to follow.")
    else:
        for sym in pinned:
            with st.container(border=True):
                c1, c2, c3 = st.columns([4, 1.2, 1.1], vertical_alignment="center")
                with c1:
                    try:
                        hist = fetch_market_history(sym)
                        last = float(hist['Close'].iloc[-1]); prev = float(hist['Close'].iloc[-2])
                        st.markdown(f"#### ✦ {sym}  ·  ${last:,.2f}")
                        st.caption(f"{(last/prev-1)*100:+.2f}% from previous close · As of {hist.index[-1].strftime('%Y-%m-%d')}")
                    except Exception:
                        st.markdown(f"#### ✦ {sym}"); st.caption("Quote unavailable")
                if c2.button("View stats ↗", key=f"watchview_{sym}", use_container_width=True):
                    st.session_state.watch_detail = sym; st.rerun()
                if c3.button("Unpin", key=f"watchremove_{sym}", use_container_width=True):
                    save_pins([x for x in pinned if x != sym])
                    if st.session_state.get('watch_detail') == sym: st.session_state.watch_detail = None
                    st.rerun()
    selected = st.session_state.get('watch_detail')
    if selected:
        st.divider()
        with st.container(border=True):
            st.markdown("#### ✦ STOCK PROFILE / FULL MARKET STATS")
            asset_detail(selected)
            if selected not in pinned and st.button(f"☆ Pin {selected} to watchlist", key="pin_detail"):
                save_pins(pinned + [selected]); st.rerun()
    st.caption("Pins are saved locally in noctis_watchlist.json next to analytics.py. They are not real brokerage holdings.")


def beginner_guide():
    st.markdown('<div class="beginner-hero"><div class="beginner-kicker">NOCTIS LEARNING ACADEMY</div><div class="beginner-title">STOCKS FOR BEGINNERS</div><div class="beginner-sub">Learn how markets work before you put real money at risk.</div></div>', unsafe_allow_html=True)
    st.warning("IMPORTANT: Stock prices can fall and you can lose your entire investment. Nothing here guarantees a return.")
    lessons = [
        ("01 / What exactly is a stock?", "Buying a share means owning a small part of a business. Prices move as investors change what they're willing to pay. You can benefit from price appreciation and, for some companies, dividends—but neither is guaranteed.", "Try this: Find a company you know, look up its ticker, and compare its price today with a year ago."),
        ("02 / Exchanges, tickers and trading hours", "Public shares trade on exchanges such as the NYSE and Nasdaq. Each listing has a ticker, such as AAPL. Regular US stock-market hours are generally 9:30 a.m. to 4:00 p.m. Eastern on trading days. Extended-hours prices can be less liquid and more volatile.", "Try this: Look at a daily candle and identify the opening and closing prices."),
        ("03 / Stocks, ETFs and index funds", "A single stock concentrates risk in one company. An exchange-traded fund (ETF) can hold many stocks or other assets. Broad-market index funds seek to track an index; diversification can reduce company-specific risk, but it cannot prevent market losses.", "Try this: Compare AAPL with SPY or VOO in NOCTIS."),
        ("04 / Reading candlestick charts", "Each candle shows open, high, low and close for one period. The body spans opening and closing prices, while the wicks show the range. A chart describes past trading; patterns do not guarantee future prices.", "Try this: Switch between 1-month and 1-year chart ranges."),
        ("05 / Market orders, limit orders and spreads", "A market order prioritizes execution but does not guarantee the price. A limit order controls the worst price you're willing to accept but may never execute. The bid-ask spread is the gap between quoted buying and selling prices.", "Try this: Practice placing a hypothetical order in the paper-trading ledger."),
        ("06 / Risk, volatility and position sizing", "Volatility measures how much prices fluctuate. Before investing, consider emergency savings, high-interest debt, time horizon, and how much loss you can tolerate. Avoid treating a single prediction or social-media post as certainty.", "Try this: Imagine a position falling 20%; calculate the dollar impact before making a decision."),
        ("07 / How to research a company", "Review revenue, net income, debt, cash flow, and risks. Public US companies publish reports such as Form 10-K (annual) and 10-Q (quarterly) through SEC EDGAR. Valuation measures like price-to-earnings need context.", "Try this: Open SEC EDGAR and search for the company's most recent 10-K."),
        ("08 / Dividends, taxes and fees", "Some companies distribute cash dividends, but they can be reduced or eliminated. Trading costs, fund expense ratios, taxes, and account fees all affect net returns. Tax rules depend on your circumstances and jurisdiction.", "Try this: Compare the expense ratios of two ETFs using their official fund pages."),
        ("09 / Scams, hype and misleading forecasts", "Watch for guaranteed-return claims, pressure to act immediately, fake account screenshots, and unregistered sellers. A backtested model can overfit historical data and fail in live markets.", "Try this: Check an investment professional through Investor.gov before trusting a solicitation."),
        ("10 / Your first practice workflow", "Choose a familiar business or broad-market ETF, read its public disclosures, add it to your watchlist, study the price history, and record a paper trade. Review what happened over time before considering any real investment.", "Try this: Pin a stock, open its profile, and write down one reason it might rise and one reason it might fall."),
    ]
    for title, explanation, exercise in lessons:
        with st.expander(title, expanded=title.startswith('01')):
            st.write(explanation)
            st.markdown(f'<div class="learning-tip"><strong>✦ PRACTICE</strong><p>{exercise}</p></div>', unsafe_allow_html=True)
    st.markdown("### VERIFIED PUBLIC LEARNING RESOURCES")
    st.link_button("Investor.gov — Introduction to Investing ↗", "https://www.investor.gov/introduction-investing")
    st.link_button("FINRA — Investor Education ↗", "https://www.finra.org/investors")
    st.link_button("SEC EDGAR — Company Filings ↗", "https://www.sec.gov/edgar/search/")
    st.link_button("Investor.gov — Check an Investment Professional ↗", "https://www.investor.gov/introduction-investing/investing-basics/investment-professionals")
    st.caption("Educational information only, not personalized financial advice.")


def trading_terminal():
    st.subheader("TRADING TERMINAL")
    st.caption("MARKET OVERVIEW • STOCK DISCOVERY • WATCHLIST SHORTCUTS")
    market_overview()


def trader_forums_page():
    st.markdown('<div class="terminal-hero"><div class="terminal-kicker">✦ NOCTIS / COMMUNITY</div><div class="terminal-title">TRADER <span>FORUMS</span></div><div class="terminal-sub">Jump to original stock discussions and public trading ideas.</div></div>', unsafe_allow_html=True)
    symbol = st.text_input("FIND DISCUSSIONS BY TICKER", value=st.session_state.get("terminal_research_symbol", "NVDA"), key="forum_ticker").strip().upper()
    if symbol:
        trader_community(symbol, symbol)


@st.cache_data(ttl=120, show_spinner=False)
def volume_snapshot(symbols):
    rows = []
    for sym in symbols:
        try:
            hist = yf.Ticker(sym).history(period="5d", interval="1d", auto_adjust=False)
            if hist.empty or "Volume" not in hist:
                continue
            latest = hist.iloc[-1]
            volume = int(latest["Volume"])
            prev = float(hist["Close"].iloc[-2]) if len(hist) > 1 else float(latest["Close"])
            change = (float(latest["Close"]) / prev - 1) * 100 if prev else 0
            rows.append({"Symbol": sym, "Volume (shares/units)": volume, "Last ($)": round(float(latest["Close"]), 2), "Change (%)": round(change, 2), "Session": str(hist.index[-1].date())})
        except Exception:
            pass
    return rows


@st.fragment(run_every="120s")
def live_volume_board(symbols):
    rows = volume_snapshot(tuple(symbols))
    st.caption(f"Last checked: {datetime.now().strftime('%H:%M:%S')} local • Rechecks every 2 minutes • Daily reported volume, not a streaming exchange feed")
    if not rows:
        st.warning("Volume data unavailable. Try again when the data provider responds.")
        return
    df = pd.DataFrame(rows).sort_values("Volume (shares/units)", ascending=False)
    st.dataframe(df, use_container_width=True, hide_index=True)
    fig = go.Figure(go.Bar(x=df["Symbol"], y=df["Volume (shares/units)"], marker_color="#B47AFF"))
    fig.update_layout(height=360, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#EEE"), yaxis=dict(gridcolor="#37313F"), margin=dict(l=10,r=10,t=10,b=10))
    st.plotly_chart(fig, use_container_width=True)


def market_volume_page():
    st.markdown('<div class="terminal-hero"><div class="terminal-kicker">✦ NOCTIS / ACTIVITY MONITOR</div><div class="terminal-title">MARKET <span>VOLUME</span></div><div class="terminal-sub">Automatically refreshing activity board for selected stocks and ETFs.</div></div>', unsafe_allow_html=True)
    st.info("This board refreshes approximately every two minutes while the page is open. Yahoo Finance volume may be delayed, incomplete during the session, or zero outside market hours. It is not tick-by-tick live data.")
    choices = {"Large-cap technology": ["NVDA", "AAPL", "MSFT", "AMD", "TSLA", "META", "AMZN", "GOOGL"], "Major ETFs": ["SPY", "QQQ", "IWM", "DIA", "VOO", "SMH"], "Active retail stocks": ["PLTR", "SOFI", "HOOD", "COIN", "INTC", "RIVN", "F", "NIO"], "My watchlist": load_pins()}
    group = st.selectbox("VOLUME BOARD", list(choices), key="volume_group")
    symbols = choices[group][:12]
    if symbols:
        live_volume_board(symbols)
    else:
        st.info("Pin stocks to My Watchlist to see their volume here.")


@st.cache_data(ttl=900, show_spinner=False)
def pokemon_card_lookup(query):
    # Optional public Pokémon TCG API, subject to provider rate limits.
    endpoint = "https://api.pokemontcg.io/v2/cards?" + urlencode({"q": 'name:"' + query.replace('"', '') + '"', "pageSize": 24, "select": "id,name,set,number,tcgplayer,cardmarket,images,rarity"})
    req = Request(endpoint, headers={"User-Agent": "NOCTIS-LocalResearch/1.0"})
    with urlopen(req, timeout=9) as response:
        return json.loads(response.read(750000)).get("data", [])


FEATURED_CARDS = [
    {"name":"Charizard", "set":"Base Set", "number":"4/102", "id":"base1-4", "rarity":"Holo Rare"},
    {"name":"Blastoise", "set":"Base Set", "number":"2/102", "id":"base1-2", "rarity":"Holo Rare"},
    {"name":"Venusaur", "set":"Base Set", "number":"15/102", "id":"base1-15", "rarity":"Holo Rare"},
    {"name":"Umbreon VMAX", "set":"Evolving Skies", "number":"215/203", "id":"swsh7-215", "rarity":"Secret Rare"},
    {"name":"Pikachu", "set":"Base Set", "number":"58/102", "id":"base1-58", "rarity":"Common"},
    {"name":"Mewtwo", "set":"Base Set", "number":"10/102", "id":"base1-10", "rarity":"Holo Rare"},
]


def pokemon_market_page():
    st.markdown("""<div class='alt-hero'><div class='alt-eyebrow'>✦ NOCTIS / COLLECTIBLES INTELLIGENCE</div>
    <div class='alt-title'>POKÉMON <span>MARKET EXPLORER</span></div>
    <div class='alt-sub'>Browse iconic cards, see their artwork, research recent sales and compare published price references when available.</div></div>""", unsafe_allow_html=True)

    st.markdown("""<style>
    .pokemon-ribbon {padding:15px 20px;border:1px solid #f5cf54;border-radius:16px;background:linear-gradient(110deg,#25202d,#182e32);margin:8px 0 18px;}
    .pokemon-ribbon b {color:#ffe17a;letter-spacing:1px;}
    .pokemon-ribbon span {color:#d3cce0;}
    </style>""", unsafe_allow_html=True)
    st.markdown('<div class="pokemon-ribbon"><b>⚡ CARD SHOWCASE</b><br><span>Artwork gallery · individual card research · live API lookup when available</span></div>', unsafe_allow_html=True)

    st.subheader("Featured card gallery")
    st.caption("The featured gallery is always available. Artwork is loaded from the Pokémon TCG image CDN; an internet connection is needed.")
    featured_cols = st.columns(3)
    for i, card in enumerate(FEATURED_CARDS):
        with featured_cols[i % 3]:
            with st.container(border=True):
                # Stable card IDs provide a useful gallery even if the card-search API is rate-limited.
                st.image(f"https://images.pokemontcg.io/{card['id'].replace('-', '/')}.png", use_container_width=True)
                st.markdown(f"**{card['name']}**")
                st.caption(f"{card['set']} · #{card['number']} · {card['rarity']}")
                if st.button("Inspect card ✦", key=f"featured_{card['id']}", use_container_width=True):
                    st.session_state["pokemon_selected_card"] = card
                    st.rerun()

    selected = st.session_state.get("pokemon_selected_card")
    if selected:
        st.divider()
        st.subheader(f"✦ Card dossier / {selected['name']}")
        a, b = st.columns([1, 2])
        with a:
            st.image(f"https://images.pokemontcg.io/{selected['id'].replace('-', '/')}.png", use_container_width=True)
        with b:
            st.markdown(f"### {selected['name']}")
            st.write(f"**Set:** {selected['set']}")
            st.write(f"**Card number:** {selected['number']}")
            st.write(f"**Rarity:** {selected['rarity']}")
            st.info("Card condition and grading change its value dramatically. No live price is claimed without a provider quote.")
            query = quote_plus(f"{selected['name']} {selected['set']} {selected['number']} pokemon card")
            st.link_button("View completed eBay sales ↗", f"https://www.ebay.com/sch/i.html?_nkw={query}&LH_Sold=1&LH_Complete=1", use_container_width=True)
            st.link_button("Compare PriceCharting ↗", f"https://www.pricecharting.com/search-products?type=prices&q={query}", use_container_width=True)
            st.link_button("Search TCGplayer ↗", f"https://www.tcgplayer.com/search/pokemon/product?productLineName=pokemon&q={query}", use_container_width=True)
            if st.button("Close card dossier"):
                st.session_state.pop("pokemon_selected_card", None)
                st.rerun()

    st.divider()
    st.subheader("Search the card database")
    query = st.text_input("Card name", value="Charizard", placeholder="Charizard, Pikachu, Umbreon...", key="pokemon_card_search").strip()
    c1, c2 = st.columns([1, 3])
    with c1:
        search_clicked = st.button("Search cards", use_container_width=True, key="pokemon_lookup")
    with c2:
        st.caption("Search is on demand. This avoids repeated API requests every time you click a gallery card.")
    if search_clicked:
        st.session_state["pokemon_last_query"] = query
    lookup = st.session_state.get("pokemon_last_query", "")
    if lookup:
        try:
            with st.spinner("Loading card records and artwork..."):
                cards = pokemon_card_lookup(lookup)
        except Exception as exc:
            cards = []
            st.warning("The live card database is unavailable or rate-limited. The featured gallery above remains usable.")
            with st.expander("Connection details"):
                st.code(str(exc)[:300])
        if cards:
            st.success(f"Loaded {len(cards)} card records for {lookup}.")
            for i in range(0, len(cards), 3):
                cols = st.columns(3)
                for col, card in zip(cols, cards[i:i+3]):
                    with col:
                        with st.container(border=True):
                            images = card.get("images") or {}
                            url = images.get("large") or images.get("small")
                            if url and url.startswith("https://"):
                                st.image(url, use_container_width=True)
                            st.markdown(f"**{card.get('name','Unknown')}**")
                            setname = (card.get("set") or {}).get("name", "Unknown set")
                            st.caption(f"{setname} · #{card.get('number','?')} · {card.get('rarity','Rarity not listed')}")
                            groups = (card.get("tcgplayer") or {}).get("prices") or {}
                            quotes = [(label, value.get("market")) for label, value in groups.items() if isinstance(value,dict) and isinstance(value.get("market"),(int,float))]
                            if quotes:
                                for label, value in quotes[:3]:
                                    st.write(f"{label}: **${value:,.2f}**")
                            else:
                                st.caption("No published price reference")
                            q = quote_plus(f"{card.get('name','')} {setname} {card.get('number','')} pokemon card")
                            st.link_button("Check sold listings ↗", f"https://www.ebay.com/sch/i.html?_nkw={q}&LH_Sold=1&LH_Complete=1", use_container_width=True)
            rows = []
            for card in cards:
                groups = (card.get("tcgplayer") or {}).get("prices") or {}
                values = [v.get("market") for v in groups.values() if isinstance(v,dict) and isinstance(v.get("market"),(int,float))]
                if values:
                    rows.append({"Card":f"{card.get('name','')} / {(card.get('set') or {}).get('name','')}","Reference price ($)":max(values)})
            if rows:
                st.subheader("Published price comparison")
                st.caption("One-time reference prices for different card versions, not a historical stock chart.")
                df = pd.DataFrame(rows).sort_values("Reference price ($)", ascending=False).head(12)
                fig = go.Figure(go.Bar(x=df["Reference price ($)"],y=df["Card"],orientation="h",marker_color="#D0A2FF"))
                fig.update_layout(height=max(340,len(df)*42),paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",font=dict(color="#F0E8F8"),yaxis=dict(autorange="reversed"))
                st.plotly_chart(fig,use_container_width=True)
        elif search_clicked:
            st.info("No cards returned. Try another name or use the featured gallery.")

    with st.expander("How to evaluate a Pokémon card before buying or selling"):
        st.markdown("**1.** Match name, set, collector number, language, finish and edition.\n\n**2.** Check raw condition versus PSA/CGC/BGS grade.\n\n**3.** Compare completed sales, not only active asking prices.\n\n**4.** Check the date, currency and quantity of comparable sales.\n\n**5.** Be careful with extremely rare cards: one unusual sale is not a reliable market price.")


def sportsbook_research_page():
    st.markdown('<div class="terminal-hero"><div class="terminal-kicker">✦ NOCTIS / ODDS INTELLIGENCE</div><div class="terminal-title">SPORTS & <span>PREDICTION MARKETS</span></div><div class="terminal-sub">Compare public research destinations and inspect event probabilities without placing bets.</div></div>', unsafe_allow_html=True)
    st.warning("Information only. Market-implied probabilities reflect prices and fees, not guaranteed outcomes. Access, legality, and age requirements vary by jurisdiction.")
    st.markdown("### Prediction market research")
    c1, c2 = st.columns(2)
    with c1:
        with st.container(border=True):
            st.markdown("#### Polymarket")
            st.write("Browse event markets, prices and publicly displayed trading activity.")
            st.link_button("Open Polymarket ↗", "https://polymarket.com/", use_container_width=True)
    with c2:
        with st.container(border=True):
            st.markdown("#### Kalshi")
            st.write("Explore event contracts and public market information.")
            st.link_button("Open Kalshi ↗", "https://kalshi.com/markets", use_container_width=True)
    st.markdown("### Sports odds research")
    c1, c2 = st.columns(2)
    with c1:
        st.link_button("ESPN scores & schedules ↗", "https://www.espn.com/", use_container_width=True)
        st.link_button("DraftKings sportsbook ↗", "https://sportsbook.draftkings.com/", use_container_width=True)
    with c2:
        st.link_button("FanDuel sportsbook ↗", "https://sportsbook.fanduel.com/", use_container_width=True)
        st.link_button("Sports Reference ↗", "https://www.sports-reference.com/", use_container_width=True)
    st.caption("External websites may require accounts or may be unavailable in your area. No live sportsbook API, account linking, or bet placement is included.")
    st.divider()
    st.markdown("### Probability explorer")
    odds = st.number_input("Decimal odds (example only)", min_value=1.01, max_value=1000.0, value=2.00, step=0.05, key="sports_odds")
    st.metric("Raw implied probability", f"{100 / odds:.2f}%")
    st.caption("1 / decimal odds, before bookmaker margin or fees. Not a calibrated forecast.")
    with st.expander("Compare implied probabilities across example odds"):
        example_odds = [1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 4.0, 5.0]
        fig = go.Figure(go.Bar(x=[str(x) for x in example_odds], y=[100 / x for x in example_odds], marker_color="#24D6C8"))
        fig.update_layout(title="Illustrative decimal odds vs implied probability", xaxis_title="Decimal odds", yaxis_title="Implied probability (%)", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#E4F5F3"), height=350)
        st.plotly_chart(fig, use_container_width=True)
        st.caption("These are mathematical examples, not live prices from sportsbooks.")
    with st.expander("Sports research checklist and public data sources"):
        st.markdown("Check injuries, lineup confirmations, travel/rest, recent performance, sample size, market timestamp, fees and bookmaker margin. Compare the underlying event definition before comparing probabilities.")
        st.link_button("ESPN schedules and scores ↗", "https://www.espn.com/")
        st.link_button("Sports Reference statistics ↗", "https://www.sports-reference.com/")



def trading_asset_workspace():
    st.subheader("STOCK SEARCH / RESEARCH")
    st.caption("HISTORICAL MARKET DATA • PAPER TRADING ONLY")

    symbols = {"Apple": "AAPL", "Microsoft": "MSFT", "NVIDIA": "NVDA", "S&P 500 ETF": "SPY", "Bitcoin (USD)": "BTC-USD", "Tesla": "TSLA"}
    left, mid, right = st.columns([2, 2, 1])
    with left:
        preset = st.selectbox("POPULAR SYMBOLS", list(symbols), key="trading_ticker")
    with mid:
        custom = st.text_input("SEARCH ANY TICKER", placeholder="Search Apple, AMD, Palantir, Bitcoin or a ticker...", key="custom_ticker").strip().upper()
    if custom and not re.fullmatch(r"[A-Z0-9.^=\-]{1,20}", custom):
        st.warning("Search with a ticker or a company name.")
        return
    if custom:
        matches = search_assets(custom)
        if matches:
            options = {f"{label}  ·  {symbol}": symbol for symbol, label in matches}
            picked = st.selectbox("MATCHING COMPANIES / SELECT TO ANALYZE", list(options), key="terminal_search_result")
            ticker = options[picked]
        else:
            ticker = custom
    else:
        ticker = symbols[preset]
    name = ticker
    if not re.fullmatch(r"[A-Z0-9.^=\-]{1,20}", ticker):
        st.warning("Enter a valid ticker symbol, for example AAPL or BTC-USD.")
        return
    with right:
        st.write("")
        st.write("")
        if st.button("Refresh prices"):
            fetch_market_history.clear()
            st.rerun()
    pinned = load_pins()
    if ticker in pinned:
        if st.button(f"★ Unpin {ticker}"):
            save_pins([x for x in pinned if x != ticker])
            st.rerun()
    else:
        if st.button(f"☆ Pin {ticker} to watchlist"):
            save_pins(pinned + [ticker])
            st.rerun()

    try:
        with st.spinner("Loading market history..."):
            history = fetch_market_history(ticker)
    except Exception as exc:
        st.error("Market data could not be loaded. Check your internet connection or try again later.")
        st.caption(f"Provider detail: {str(exc)[:180]}")
        return

    last = float(history["Close"].iloc[-1])
    previous = float(history["Close"].iloc[-2])
    change = (last / previous - 1) * 100
    asof = history.index[-1]
    st.caption(f"Source: Yahoo Finance via yfinance • Last available daily candle: {asof.strftime('%Y-%m-%d')} • Adjusted historical OHLC • May be delayed")

    a, b, c, d = st.columns(4)
    a.metric("LATEST DAILY CLOSE", f"${last:,.2f}", f"{change:+.2f}% vs prior close")
    b.metric("30-SESSION HIGH", f"${history['High'].tail(30).max():,.2f}")
    c.metric("30-SESSION LOW", f"${history['Low'].tail(30).min():,.2f}")
    d.metric("HISTORY", f"{len(history):,} daily candles")

    chart_tab, trades_tab, forecast_tab = st.tabs(["CANDLESTICKS", "PAPER TRADES & HISTORY", "AI FORECAST LAB"])
    with chart_tab:
        window = st.select_slider("Chart range", options=["1M", "3M", "6M", "1Y", "2Y"], value="6M")
        days = {"1M": 22, "3M": 65, "6M": 130, "1Y": 252, "2Y": 504}[window]
        shown = history.tail(days)
        fig = go.Figure(go.Candlestick(
            x=shown.index, open=shown["Open"], high=shown["High"],
            low=shown["Low"], close=shown["Close"],
            increasing_line_color="#f5f5f5", decreasing_line_color="#888888",
            increasing_fillcolor="#ededed", decreasing_fillcolor="#555555",
            name=ticker,
        ))
        fig.update_layout(
            height=480, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#eeeeee"), xaxis_rangeslider_visible=False,
            xaxis=dict(showgrid=False), yaxis=dict(gridcolor="#333333", title="USD"),
            margin=dict(l=10, r=10, t=25, b=10),
        )
        st.plotly_chart(fig, use_container_width=True)
        st.caption("Daily candles, not streaming intraday quotes. Bitcoin trades every day; stocks trade on market sessions.")

    with trades_tab:
        st.subheader("Paper trading ledger")
        st.caption("Demo orders use the latest available daily close, not an executable market quote. Trades are not sent to a broker.")
        if "noctis_ledger" not in st.session_state:
            st.session_state.noctis_ledger = []
        with st.form("paper_order", clear_on_submit=False):
            c1, c2, c3 = st.columns(3)
            with c1:
                side = st.selectbox("Action", ["BUY", "SELL"])
            with c2:
                order_symbol = st.selectbox("Asset", list(dict.fromkeys([ticker] + list(symbols.values()) + load_pins())))
            with c3:
                quantity = st.number_input("Quantity", min_value=0.01, value=1.0, step=1.0)
            submit = st.form_submit_button("Record paper trade")
        if submit:
            symbol = order_symbol
            try:
                price = float(fetch_market_history(symbol)["Close"].iloc[-1])
                owned = sum((t["Quantity"] if t["Action"] == "BUY" else -t["Quantity"]) for t in st.session_state.noctis_ledger if t["Symbol"] == symbol)
                if side == "SELL" and quantity > owned + 1e-8:
                    st.error(f"Cannot sell {quantity:g}: only {owned:g} paper units held.")
                else:
                    st.session_state.noctis_ledger.append({
                        "Recorded at (UTC)": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                        "Action": side, "Symbol": symbol, "Quantity": float(quantity),
                        "Demo fill ($)": round(price, 4),
                    })
                    st.success(f"Recorded {side} {quantity:g} {symbol} at demo price ${price:,.2f}")
            except Exception:
                st.error("Could not load the asset price. No trade recorded.")

        ledger = st.session_state.noctis_ledger
        if ledger:
            frame = pd.DataFrame(ledger)
            st.dataframe(frame, use_container_width=True, hide_index=True)
            st.download_button("Download trade history (CSV)", frame.to_csv(index=False), file_name="noctis_paper_trades.csv", mime="text/csv")
            st.subheader("Open paper positions")
            positions = []
            for sym in sorted(set(frame["Symbol"])):
                trades = [t for t in ledger if t["Symbol"] == sym]
                held = sum(t["Quantity"] if t["Action"] == "BUY" else -t["Quantity"] for t in trades)
                if held > 1e-8:
                    # Weighted-average cost accounting; sales reduce quantity at average cost.
                    units, basis = 0.0, 0.0
                    for t in trades:
                        if t["Action"] == "BUY":
                            basis += t["Quantity"] * t["Demo fill ($)"]
                            units += t["Quantity"]
                        elif units > 0:
                            basis -= (basis / units) * t["Quantity"]
                            units -= t["Quantity"]
                    try:
                        market = float(fetch_market_history(sym)["Close"].iloc[-1])
                        positions.append({"Symbol": sym, "Quantity": round(held, 4), "Market value ($)": round(held * market, 2), "Unrealized P/L ($)": round(held * market - basis, 2)})
                    except Exception:
                        st.warning(f"Could not value {sym} right now.")
            if positions:
                st.dataframe(pd.DataFrame(positions), use_container_width=True, hide_index=True)
            if st.button("Clear paper trade history"):
                st.session_state.noctis_ledger = []
                st.rerun()
        else:
            st.info("No paper trades yet. Record a BUY to start your history.")
        st.caption("Paper trade history lives in this browser session. Download CSV to keep a copy; it is not a permanent account or brokerage record.")

    with forecast_tab:
        st.subheader(f"Experimental AI forecast / {ticker}")
        st.write("A small random-forest model uses past daily returns, short-term momentum, and volatility to estimate the next trading day's percentage change.")
        with st.spinner("Training and checking historical forecasts..."):
            result = evaluate_forecast(history)
        if result is None:
            st.warning("Not enough history for this model.")
        else:
            mae, accuracy, next_prediction, comparison = result
            m1, m2, m3 = st.columns(3)
            m1.metric("NEXT-SESSION MODEL ESTIMATE", f"{next_prediction:+.2f}%")
            m2.metric("HOLDOUT DIRECTION ACCURACY", f"{accuracy:.1f}%")
            m3.metric("HOLDOUT MEAN ERROR", f"{mae:.2f} pp")
            st.line_chart(comparison.tail(45))
            st.caption("Historical test: first 80% of labeled days used for training, final 20% held out. The chart compares model predictions with actual next-session changes. No future outcome is known for the newest estimate.")
            st.warning("Research demonstration only. This model is not validated for live trading, does not account for trading costs, and may perform worse than chance. Not financial advice.")


def gambling_research():
    st.subheader("GAMBLING SITE RESEARCH")
    st.caption("Public information and tools • No betting integration, accounts, or wagering")
    st.info("This section is a research workspace, not a live odds feed. Gambling laws and site availability vary by location. Check licensing and eligibility before using a service.")

    st.markdown("#### Open a website you want to research")
    website = st.text_input("Website address", placeholder="https://example.com", key="research_site_url")
    if website:
        from urllib.parse import urlparse
        parsed = urlparse(website.strip())
        if parsed.scheme in ("https", "http") and parsed.netloc and not any(c.isspace() for c in website):
            st.link_button("Open website ↗", website.strip())
        else:
            st.warning("Enter a complete http:// or https:// website address.")

    st.markdown("#### Decimal odds calculator")
    c1, c2 = st.columns(2)
    with c1:
        decimal_odds = st.number_input("Decimal odds", min_value=1.01, value=2.00, step=0.05)
    with c2:
        stake = st.number_input("Example stake ($)", min_value=0.0, value=10.0, step=5.0)
    a, b, c = st.columns(3)
    a.metric("Implied probability", f"{100 / decimal_odds:.1f}%")
    b.metric("Potential total return", f"${stake * decimal_odds:,.2f}")
    c.metric("Potential net profit", f"${stake * (decimal_odds - 1):,.2f}")
    st.caption("Hypothetical calculations only. These figures exclude fees, taxes, and any other outcomes. Odds imply a probability, not a prediction of what will happen.")

    st.markdown("#### Public information")
    st.link_button("American Gaming Association — state gaming regulations ↗", "https://www.americangaming.org/state-of-play/")
    st.link_button("National Council on Problem Gambling ↗", "https://www.ncpgambling.org/")
    st.caption("NOCTIS does not recommend gambling sites or place bets.")


@st.cache_data(ttl=1800, show_spinner=False)
def youtube_recent_uploads(channel_id):
    """YouTube's public channel Atom feed; no API key required, if accessible."""
    url = f"https://www.youtube.com/feeds/videos.xml?channel_id={channel_id}"
    request = Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; NOCTIS/1.0)"})
    with urlopen(request, timeout=9) as response:
        data = response.read(250000)
    root = ET.fromstring(data)
    atom = "{http://www.w3.org/2005/Atom}"
    yt = "{http://www.youtube.com/xml/schemas/2015}"
    items = []
    for entry in root.findall(f"{atom}entry"):
        title = entry.findtext(f"{atom}title", default="Video")
        video_id = entry.findtext(f"{yt}videoId", default="")
        published = entry.findtext(f"{atom}published", default="")
        if re.fullmatch(r"[A-Za-z0-9_-]{11}", video_id):
            items.append({"title": title, "video_id": video_id, "published": published[:16].replace("T", " ") + " UTC"})
    return items


def market_videos():
    st.subheader("MARKET VIDEOS & LIVE")
    st.caption("Public YouTube videos and links to live trading coverage. Live status is determined by YouTube, not NOCTIS.")

    search_term = st.text_input("SEARCH YOUTUBE FOR MARKET COVERAGE", value="stock market live", key="video_search_term").strip()
    query = quote_plus(search_term or "stock market live")
    a, b = st.columns(2)
    with a:
        st.link_button("Find live market streams ↗", f"https://www.youtube.com/results?search_query={query}&sp=EgJAAQ%253D%253D", use_container_width=True)
    with b:
        st.link_button("Find recent market videos ↗", f"https://www.youtube.com/results?search_query={query}&sp=CAI%253D", use_container_width=True)
    st.caption("Search results open on YouTube; stream availability and upload times can change.")

    st.divider()
    st.markdown("#### Recent uploads from market news channels")
    sources = {
        "CNBC Television": "UCvJJ_dzjViJCoLf5uKUTwoA",
        "Bloomberg Television": "UChirEOpgFCupRAk5etXqPaA",
    }
    source = st.selectbox("Channel", list(sources), key="video_channel")
    try:
        items = youtube_recent_uploads(sources[source])
    except Exception:
        items = []
    if items:
        for item in items[:6]:
            with st.container(border=True):
                st.markdown(f"**{item['title']}**")
                st.caption(f"Published: {item['published']} • {source}")
                st.link_button("Watch on YouTube ↗", f"https://www.youtube.com/watch?v={item['video_id']}")
                if st.button("Play here", key=f"play_{item['video_id']}"):
                    st.session_state["noctis_video_id"] = item["video_id"]
                    st.session_state["noctis_video_url"] = ""
                if st.session_state.get("noctis_video_id") == item["video_id"] and not st.session_state.get("noctis_video_url"):
                    st.video(f"https://www.youtube.com/watch?v={item['video_id']}")
                    st.caption("Video player appears directly under the selected upload. Embedding is controlled by YouTube and the video owner.")
    else:
        st.info("Recent uploads could not be retrieved from this channel right now. Use the YouTube search links above or paste a video URL below.")

    st.divider()
    st.markdown("#### Video player")
    url = st.text_input("Paste a YouTube video or livestream URL", placeholder="https://www.youtube.com/watch?v=...", key="video_url")
    chosen = st.session_state.get("noctis_video_id")
    if url:
        parsed = urlparse(url.strip())
        host = (parsed.hostname or "").lower()
        candidate = ""
        if host in ("youtube.com", "www.youtube.com", "m.youtube.com"):
            if parsed.path == "/watch":
                candidate = parse_qs(parsed.query).get("v", [""])[0]
            elif parsed.path.startswith(("/live/", "/shorts/", "/embed/")):
                candidate = parsed.path.split("/")[2]
        elif host == "youtu.be":
            candidate = parsed.path.strip("/").split("/")[0]
        if re.fullmatch(r"[A-Za-z0-9_-]{11}", candidate):
            chosen = candidate
        else:
            st.warning("Please enter a valid YouTube video or livestream URL.")
            chosen = None
    if chosen and url:
        st.video(f"https://www.youtube.com/watch?v={chosen}")
        st.caption("Playback depends on whether the video owner permits embedding. Some livestreams may only play on YouTube.")


st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=Space+Grotesk:wght@400;500;600;700&display=swap');
:root {--noctis-purple:#B47AFF;--noctis-purple-bright:#D9B8FF;--noctis-bg:#090A0E;--noctis-card:#15161D;--noctis-line:#34303E;--noctis-muted:#A8A7B4;--noctis-yellow:#FFD76B;}
html,body,[class*="css"],.stApp {font-family:'DM Sans',sans-serif;}
.stApp {background:radial-gradient(ellipse 55% 28% at 88% 0%,#251532 0%,transparent 80%),radial-gradient(ellipse 40% 35% at 0% 100%,#171123 0%,transparent 90%),var(--noctis-bg);color:#F3F1F8;}
.block-container {max-width:1500px;padding-top:2rem;padding-bottom:5rem;}
h1,h2,h3,h4 {font-family:'Space Grotesk',sans-serif!important;color:#F9F7FF!important;letter-spacing:-.035em;line-height:1.18;}
h1 {font-size:2.15rem!important;font-weight:700!important;}
h2 {font-size:1.5rem!important;font-weight:650!important;}
h3 {font-size:1.18rem!important;font-weight:650!important;}
p,li {line-height:1.65;}
[data-testid="stCaptionContainer"],small {color:var(--noctis-muted)!important;letter-spacing:.012em;}
hr {border-color:#292630!important;margin:1.25rem 0!important;}
/* Sidebar: crisp, spacious, clear active navigation */
[data-testid="stSidebar"] {background:linear-gradient(180deg,#15111D 0%,#0D0E13 65%,#0B0C10 100%);border-right:1px solid #3A294D;}
[data-testid="stSidebar"] [data-testid="stSidebarUserContent"] {padding-top:2.2rem;}
[data-testid="stSidebar"] h1 {font-size:2rem!important;letter-spacing:.025em;color:#F4E9FF!important;text-shadow:0 0 22px #9B50F34D;}
[data-testid="stSidebar"] [role="radiogroup"] {gap:.55rem;}
[data-testid="stSidebar"] [role="radiogroup"] label {border:1px solid transparent;border-radius:12px;padding:.75rem .9rem;transition:background .15s,border-color .15s;background:#FFFFFF05;}
[data-testid="stSidebar"] [role="radiogroup"] label:hover {background:#B47AFF15;border-color:#B47AFF50;}
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {background:linear-gradient(90deg,#6B39A64D,#6B39A611);border-color:#A06CE1;box-shadow:inset 3px 0 0 #C28AFF;}
[data-testid="stSidebar"] [role="radiogroup"] label p {font-weight:600;letter-spacing:.005em;}
/* Consistent dashboard surfaces */
[data-testid="stMetric"] {background:linear-gradient(140deg,#1D1A25,#111217);border:1px solid #3B3249;border-radius:15px;padding:20px 22px;box-shadow:0 8px 26px #00000020;}
[data-testid="stMetricLabel"] {color:#BDB5C9!important;font-size:.75rem!important;font-weight:700!important;letter-spacing:.075em;text-transform:uppercase;}
[data-testid="stMetricValue"] {color:#FAF8FF!important;font-family:'Space Grotesk',sans-serif;font-weight:700;letter-spacing:-.04em;}
[data-testid="stMetricDelta"] {font-weight:700;}
[data-testid="stVerticalBlockBorderWrapper"] {border-color:#383340!important;border-radius:16px!important;}
[data-testid="stVerticalBlockBorderWrapper"]:has(> div) {background-color:#FFFFFF02;}
[data-testid="stDataFrame"] {border:1px solid #463650;border-radius:13px;overflow:hidden;box-shadow:0 10px 35px #00000022;}
/* Tabs are navigation, not bare text */
.stTabs [data-baseweb="tab-list"] {gap:.4rem;border-bottom:1px solid #3A3046;padding-bottom:.4rem;flex-wrap:wrap;}
.stTabs [data-baseweb="tab"] {font-weight:700;letter-spacing:.035em;font-size:.78rem;padding:.7rem 1.1rem;border-radius:10px 10px 0 0;color:#BDB6C8;}
.stTabs [aria-selected="true"] {background:#B47AFF18!important;color:#E1C3FF!important;}
.stTabs [data-baseweb="tab-highlight"] {background-color:#B47AFF!important;height:3px;}
/* Inputs and actions */
.stButton button,.stLinkButton a,.stDownloadButton button,.stFormSubmitButton button {border-radius:10px!important;border:1px solid #69517E!important;background:linear-gradient(145deg,#292035,#1A1822)!important;color:#F7F1FF!important;font-weight:700!important;transition:border-color .15s,box-shadow .15s,transform .15s;}
.stButton button:hover,.stLinkButton a:hover,.stDownloadButton button:hover,.stFormSubmitButton button:hover {border-color:#C18CFF!important;box-shadow:0 0 0 2px #B47AFF22,0 6px 24px #9B50F329!important;transform:translateY(-1px);}
.stButton button:disabled {opacity:.5;transform:none;}
[data-baseweb="input"],[data-baseweb="select"]>div,[data-baseweb="base-input"] {border-radius:10px!important;background:#15151D!important;border-color:#494050!important;}
[data-baseweb="input"]:focus-within,[data-baseweb="base-input"]:focus-within {outline:1px solid #BA86FA!important;}
[data-testid="stWidgetLabel"] p {color:#D7CFE0!important;font-weight:700!important;font-size:.83rem!important;letter-spacing:.015em;}
[data-testid="stExpander"] {border:1px solid #443D4D!important;border-radius:12px!important;background:#15131B!important;overflow:hidden;}
[data-testid="stExpander"] summary {font-weight:700;color:#F1EAFB;}
[data-testid="stAlert"] {border-radius:12px!important;}
/* Purposeful purple hero headers */
.terminal-hero,.noctis-watch-hero {position:relative;overflow:hidden;padding:36px 36px;border:1px solid #8350B3;border-radius:20px;background:radial-gradient(ellipse at 85% 10%,#482265 0%,transparent 56%),linear-gradient(125deg,#1A1423,#111116 78%);box-shadow:0 14px 42px #00000040,0 0 28px #A45CFF12;margin:12px 0 25px;}
.terminal-hero:after,.noctis-watch-hero:after {content:'';position:absolute;right:-50px;top:-75px;width:230px;height:230px;border:1px solid #B47AFF28;border-radius:50%;box-shadow:0 0 0 32px #B47AFF0A,0 0 0 70px #B47AFF07;pointer-events:none;}
.terminal-kicker,.watch-eyebrow {color:#D9B8FF;font-size:11px;font-weight:800;letter-spacing:3px;text-transform:uppercase;}
.terminal-title,.watch-title {font-family:'Space Grotesk',sans-serif;font-size:clamp(33px,4.6vw,56px);font-weight:700;letter-spacing:-2px;line-height:1.1;color:#FFF;margin:14px 0;}
.terminal-title span,.watch-title span {color:#C493FF;text-shadow:0 0 28px #AA63FF60;}
.terminal-sub,.watch-sub {color:#C5BBD0;font-size:15px;max-width:680px;line-height:1.6;}
/* Educational yellow is reserved for important concepts */
.beginner-hero {padding:36px;border-radius:20px;border:1px solid #9C7B32;background:radial-gradient(ellipse at 90% 0%,#4D3A19,transparent 58%),linear-gradient(115deg,#241F16,#121316 80%);margin:12px 0 25px;box-shadow:0 10px 36px #00000030;}
.beginner-kicker {color:#FFE58A;font-size:11px;font-weight:800;letter-spacing:3px;}
.beginner-title {font-family:'Space Grotesk',sans-serif;font-size:clamp(30px,4vw,49px);font-weight:700;letter-spacing:-1.7px;color:#FFF5C8;margin:12px 0;}
.beginner-sub {color:#E0D5B4;line-height:1.6;}
.learning-tip {border-left:4px solid #FFD76B;background:#302917;border-radius:8px;padding:15px 18px;margin:14px 0;color:#F7EAC5;}
.learning-tip strong {color:#FFE68A;font-size:.8rem;letter-spacing:1.5px;}
.learning-tip p {margin:6px 0 0;}
@media(max-width:700px){.block-container {padding:1.1rem .8rem 3rem;}.terminal-hero,.noctis-watch-hero,.beginner-hero {padding:24px 20px;}.stTabs [data-baseweb="tab"] {padding:.55rem .7rem;font-size:.72rem;}}

/* Distinct alternative-market visual identity */
.alt-sidebar-tag {font-size:10px;letter-spacing:1.7px;font-weight:800;color:#FDE68A;padding:7px 0 11px;}
.alt-hero {border-radius:22px;padding:35px;margin:8px 0 26px;background:radial-gradient(ellipse at 85% 10%,#7041A055,transparent 52%),linear-gradient(125deg,#12252A,#1B1325 65%,#13131A);border:1px solid #CDAF56;box-shadow:0 0 32px #B47AFF20;}
.alt-eyebrow {color:#FFE57D;font-size:11px;letter-spacing:2.8px;font-weight:800;}
.alt-title {font-family:'Space Grotesk',sans-serif;font-size:clamp(28px,4.5vw,51px);font-weight:800;letter-spacing:-1.5px;color:#FFF;margin:12px 0;line-height:1.12;}
.alt-title span {color:#D8AEFF;text-shadow:0 0 22px #B47AFF66;}
.alt-sub {color:#DFD9E7;max-width:740px;line-height:1.6;}
</style>
""", unsafe_allow_html=True)

# Alternative-market research pages. These use public source links rather than
# scraping third-party discussions or claiming to have live sportsbook feeds.
def alternative_market_overview():
    st.markdown("""<div class='alt-hero'><div class='alt-eyebrow'>✦ NOCTIS / ALTERNATIVE MARKETS</div>
    <div class='alt-title'>EXPLORE <span>BEYOND STOCKS</span></div>
    <div class='alt-sub'>Collectibles, sports information, prediction markets and gaming-site research — in one dedicated workspace.</div></div>""", unsafe_allow_html=True)
    a, b, c = st.columns(3)
    with a:
        with st.container(border=True):
            st.markdown("### ⚡ Pokémon Market")
            st.write("Look up card sets, compare published price references and research completed sales.")
            if st.button("Explore Pokémon", use_container_width=True):
                st.session_state.noctis_alt_navigation = "Pokémon Card Market"
                st.rerun()
    with b:
        with st.container(border=True):
            st.markdown("### 🏟️ Sports & Predictions")
            st.write("Find sports statistics, public prediction markets and probability explainers.")
            if st.button("Explore sports", use_container_width=True):
                st.session_state.noctis_alt_navigation = "Sportsbook & Prediction Research"
                st.rerun()
    with c:
        with st.container(border=True):
            st.markdown("### 🎲 Gaming Research")
            st.write("Review public licensing, site information and odds mathematics.")
            if st.button("Explore research", use_container_width=True):
                st.session_state.noctis_alt_navigation = "Gambling Site Research"
                st.rerun()
    st.info("Price references and external websites can change. This hub does not place wagers or guarantee live odds.")


def community_links_page(category):
    titles = {
        "pokemon": ("POKÉMON COMMUNITY", "Card collecting, grading, recent sales and trading-card discussion"),
        "sports": ("SPORTS & PREDICTION FORUMS", "Sports statistics, fan discussion and public prediction-market research"),
        "gambling": ("GAMBLING RESEARCH FORUMS", "Consumer experiences, site safety, regulatory information and responsible play"),
    }
    title, subtitle = titles[category]
    st.markdown(f"<div class='alt-hero'><div class='alt-eyebrow'>✦ NOCTIS / COMMUNITY RESEARCH</div><div class='alt-title'>{html.escape(title)}</div><div class='alt-sub'>{html.escape(subtitle)}</div></div>", unsafe_allow_html=True)
    q = st.text_input("SEARCH DISCUSSION TOPIC", value={"pokemon":"Charizard PSA 10", "sports":"NBA odds", "gambling":"site licensing"}[category], key=f"alt_forum_{category}")
    search = quote_plus(q.strip() or category)
    if category == "pokemon":
        links = [
            ("Reddit / Pokémon TCG", f"https://www.reddit.com/r/PokemonTCG/search/?q={search}&restrict_sr=1&sort=new"),
            ("Reddit / Pokémon Card Value", f"https://www.reddit.com/r/PokemonCardValue/search/?q={search}&restrict_sr=1&sort=new"),
            ("eBay completed sales", f"https://www.ebay.com/sch/i.html?_nkw={search}&LH_Sold=1&LH_Complete=1"),
            ("PriceCharting search", f"https://www.pricecharting.com/search-products?type=prices&q={search}"),
        ]
    elif category == "sports":
        links = [
            ("Reddit / Sportsbook discussions", f"https://www.reddit.com/r/sportsbook/search/?q={search}&restrict_sr=1&sort=new"),
            ("Reddit / Sports discussions", f"https://www.reddit.com/r/sports/search/?q={search}&restrict_sr=1&sort=new"),
            ("ESPN schedules & scores", "https://www.espn.com/"),
            ("Sports Reference historical statistics", "https://www.sports-reference.com/"),
            ("Kalshi public event markets", "https://kalshi.com/markets"),
            ("Polymarket public event markets", "https://polymarket.com/"),
        ]
    else:
        links = [
            ("Reddit / Gambling discussions", f"https://www.reddit.com/r/gambling/search/?q={search}&restrict_sr=1&sort=new"),
            ("American Gaming Association — state regulations", "https://www.americangaming.org/state-of-play/"),
            ("National Council on Problem Gambling", "https://www.ncpgambling.org/"),
        ]
    st.caption("Opens external public pages. Posts are not imported or verified by NOCTIS; links may require sign-in.")
    for label, url in links:
        with st.container(border=True):
            left, right = st.columns([3,1])
            left.markdown(f"**{label}**")
            right.link_button("Open discussion ↗", url, use_container_width=True)
    with st.expander("How to evaluate community claims", expanded=True):
        st.write("Check publication date, original sources, and potential conflicts of interest. Opinions and screenshots do not establish accurate market prices or reliable predictions.")


@st.fragment(run_every="300s")
def alt_research_refresh():
    st.caption("⟳ Research panel checked at " + datetime.now().strftime("%H:%M:%S") + " local time. Links are not live data feeds.")
    st.caption("Pokémon price lookup caches results for 15 minutes; stock volume refreshes separately in its own page. Sportsbook odds are not automatically imported.")


if market_space == "⚡ Alternative Markets":
    st.markdown("""<style>
    .stApp {background:radial-gradient(ellipse at 85% 5%,#29133B,transparent 42%),radial-gradient(ellipse at 0% 90%,#102C31,transparent 50%),#0B0D13!important;}
    [data-testid="stSidebar"] {background:linear-gradient(180deg,#1A1427,#101A1D)!important;border-right:1px solid #765A8D!important;}
    [data-testid="stMetric"] {border-color:#75604B!important;}
    </style>""", unsafe_allow_html=True)

st.markdown("<div style='color:#B8A5CE;font-size:11px;font-weight:800;letter-spacing:2.8px;margin:0 0 6px'>✦ NOCTIS / MARKET INTELLIGENCE</div>", unsafe_allow_html=True)
st.caption("LOCAL RESEARCH TERMINAL  •  DELAYED MARKET DATA  •  PAPER TRADING")
if page == "Trading Terminal":
    trading_terminal()
elif page == "Market Volume":
    market_volume_page()
elif page == "Stock Research":
    trading_asset_workspace()
elif page == "Trader Forums":
    trader_forums_page()
elif page == "My Watchlist":
    watchlist_page()
elif page == "Stocks for Beginners":
    beginner_guide()
elif page == "Market Videos & Live":
    market_videos()
elif page == "Alternative Market Overview":
    alternative_market_overview()
elif page == "Pokémon Card Market":
    pokemon_market_page()
    alt_research_refresh()
elif page == "Pokémon Community":
    community_links_page("pokemon")
elif page == "Sportsbook & Prediction Research":
    sportsbook_research_page()
    alt_research_refresh()
elif page == "Sports & Prediction Forums":
    community_links_page("sports")
elif page == "Gambling Research Forums":
    community_links_page("gambling")
else:
    gambling_research()
    alt_research_refresh()
