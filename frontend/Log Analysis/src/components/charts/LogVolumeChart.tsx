import React, { useRef, useEffect } from "react";
import * as echarts from "echarts";
import { BORD, T, ACC } from "../../constants/theme";

export interface LogVolumeDataItem {
  label: string;   // x-axis label, e.g. "08:00"
  windows: number;
  network: number;
  syslog: number;
}

interface Props {
  ready: boolean;
  data?: LogVolumeDataItem[];
}

const HOURS = Array.from({ length: 12 }, (_, i) =>
  `${(8 + i).toString().padStart(2, "0")}:00`
);

// No data yet — empty placeholder
const DEFAULT_DATA: LogVolumeDataItem[] = HOURS.map(label => ({
  label,
  windows: 0,
  network: 0,
  syslog:  0,
}));

function buildOption(data: LogVolumeDataItem[]): echarts.EChartsOption {
  return {
    backgroundColor: "transparent",
    tooltip: {
      trigger: "axis",
      backgroundColor: "#0e2040",
      borderColor: "#1e4060",
      textStyle: { color: "#eaf4ff", fontFamily: "JetBrains Mono", fontSize: 11 },
    },
    legend: {
      top: 0,
      right: 0,
      textStyle: { color: T.md, fontSize: 10, fontFamily: "JetBrains Mono" },
      icon: "circle",
      itemWidth: 8,
      itemHeight: 8,
      itemGap: 14,
    },
    grid: { top: 36, right: 14, bottom: 28, left: 8, containLabel: true },
    xAxis: {
      type: "category",
      data: data.map(d => d.label),
      axisLabel: { color: T.lo, fontSize: 9, fontFamily: "JetBrains Mono", interval: 2 },
      axisLine: { lineStyle: { color: BORD.dim } },
      axisTick: { show: false },
    },
    yAxis: {
      type: "value",
      axisLabel: { color: T.lo, fontSize: 9, fontFamily: "JetBrains Mono" },
      splitLine: { lineStyle: { color: BORD.dim } },
    },
    series: [
      {
        name: "Windows",
        type: "bar",
        stack: "logs",
        data: data.map(d => d.windows),
        barMaxWidth: 22,
        itemStyle: { color: ACC.purple },
      },
      {
        name: "Network",
        type: "bar",
        stack: "logs",
        data: data.map(d => d.network),
        itemStyle: { color: ACC.cyan },
      },
      {
        name: "Syslog",
        type: "bar",
        stack: "logs",
        data: data.map(d => d.syslog),
        itemStyle: {
          color: ACC.green,
          borderRadius: [4, 4, 0, 0],
        },
      },
    ],
  };
}

const LogVolumeChart: React.FC<Props> = ({ ready, data }) => {
  const ref  = useRef<HTMLDivElement>(null);
  const inst = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!ready || !ref.current) return;
    inst.current = echarts.init(ref.current, "dark");
    const ro = new ResizeObserver(() => inst.current?.resize());
    ro.observe(ref.current);
    return () => { ro.disconnect(); inst.current?.dispose(); inst.current = null; };
  }, [ready]);

  useEffect(() => {
    if (!inst.current) return;
    inst.current.setOption(buildOption(data ?? DEFAULT_DATA), true);
  }, [data, ready]);

  return <div ref={ref} style={{ width: "100%", height: 260 }} />;
};

export default LogVolumeChart;
