
import streamlit as st
import plotly.graph_objects as go
import random
from datetime import datetime

st.set_page_config(
    page_title="NOCTIS Intelligence",
    page_icon="🌌",
    layout="wide"
)

st.markdown("""
<style>
.stApp {
    background:
        radial-gradient(ellipse at 85% 0%, #35105c 0%, transparent 40%),
        radial-gradient(ellipse at 0% 90%, #200c43 0%, transparent 45%),
        #090615;
    color: #f4eaff;
}

[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #180c30, #0b0719);
    border-right: 1px solid #513179;
}

h1, h2, h3 {
    color: #f4eaff !important;
}

[data-testid="stMetric"] {
    background: linear-gradient(135deg, #21123b, #120b25);
    border: 1px solid #58358a;
    border-radius: 16px;
    padding: 22px;
    box-shadow: 0 0 20px #6d28d920;
}

[data-testid="stMetricLabel"] {
    color: #cbb7e8;
}

[data-testid="stMetricValue"] {
    color: #f6edff;
}

div[data-testid="stVerticalBlockBorderWrapper"] {
    border-color: #513179 !important;
}

.stAppHeader {
    background: transparent;
}
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.title("✦ NOCTIS")
    st.caption("INTELLIGENCE PLATFORM")
    st.divider()
    st.markdown("### ◈ Overview")
    st.markdown("◷ Real-Time Analytics")
    st.markdown("◎ Audience")
    st.markdown("◇ Traffic Sources")
    st.markdown("▤ Reports")
    st.divider()
    st.success("● Demo monitoring active")

st.title("🌌 Website Traffic Intelligence")
st.caption("Real-Time Analytics • Cosmic Intelligence Dashboard")

@st.fragment(run_every="5s")
def dashboard():
    if "traffic" not in st.session_state:
        st.session_state.traffic = [500, 750, 1200, 900, 1500]

    new_visitors = random.randint(100, 2000)
    st.session_state.traffic.append(new_visitors)
    st.session_state.traffic = st.session_state.traffic[-24:]

    traffic = st.session_state.traffic
    total = sum(traffic)
    latest = traffic[-1]
    peak = max(traffic)
    average = round(total / len(traffic))

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("✧ Total Visitors", f"{total:,}")
    col2.metric("◉ Current Interval", f"{latest:,}")
    col3.metric("↗ Peak Traffic", f"{peak:,}")
    col4.metric("◇ Average Traffic", f"{average:,}")

    st.write("")

    left, right = st.columns([2, 1])

    with left:
        with st.container(border=True):
            st.subheader("✦ Visitor Activity")

            fig = go.Figure()

            fig.add_trace(go.Scatter(
                x=list(range(1, len(traffic) + 1)),
                y=traffic,
                mode="lines+markers",
                line=dict(color="#bb86fc", width=4),
                marker=dict(size=7, color="#e0b3ff"),
                fill="tozeroy",
                fillcolor="rgba(155, 89, 255, 0.18)",
                name="Visitors"
            ))

            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#cbb7e8"),
                xaxis=dict(
                    title="Recorded Interval",
                    showgrid=False
                ),
                yaxis=dict(
                    title="Visitors",
                    gridcolor="rgba(180,130,255,0.12)"
                ),
                margin=dict(l=10, r=10, t=20, b=10),
                height=360
            )

            st.plotly_chart(fig, use_container_width=True)

    with right:
        with st.container(border=True):
            st.subheader("✧ Intelligence Insights")

            if latest > average:
                st.success("Traffic is above average.")
            elif latest < average:
                st.warning("Traffic is below average.")
            else:
                st.info("Traffic is at average.")

            st.write("**Latest reading:**", f"{latest:,}")
            st.write("**Peak reading:**", f"{peak:,}")
            st.write("**Average reading:**", f"{average:,}")

            st.divider()
            st.caption("LAST UPDATED")
            st.write(datetime.now().strftime("%I:%M:%S %p"))

    st.divider()
    st.caption(
        "NOCTIS Intelligence • Simulated traffic data • "
        "Automatic updates every 5 seconds"
    )

dashboard()
