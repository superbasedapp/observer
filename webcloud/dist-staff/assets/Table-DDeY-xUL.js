import{c as i,r as m,j as e,b as j,d as r}from"./staff-ldsUI_UG.js";/**
 * @license lucide-react v0.469.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const C=i("Check",[["path",{d:"M20 6 9 17l-5-5",key:"1gmf2c"}]]);/**
 * @license lucide-react v0.469.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const S=i("ChevronRight",[["path",{d:"m9 18 6-6-6-6",key:"mthhwq"}]]);/**
 * @license lucide-react v0.469.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const E=i("Copy",[["rect",{width:"14",height:"14",x:"8",y:"8",rx:"2",ry:"2",key:"17jyea"}],["path",{d:"M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2",key:"zix9uf"}]]),u=m.createContext(null);u.Provider;function w(){return m.useContext(u)??(()=>null)}function _({title:c,icon:n,sub:s,helpId:t,right:a,className:o}){const l=w();return e.jsxs("header",{className:r("flex items-start justify-between gap-4",o),children:[e.jsxs("div",{className:"flex min-w-0 items-start gap-3",children:[n&&e.jsx("span",{"aria-hidden":!0,className:"mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-3 border border-accent/25 bg-accent-soft text-accent",children:e.jsx(j,{icon:n,size:"lg"})}),e.jsxs("div",{className:"min-w-0",children:[e.jsxs("h1",{className:"flex items-center text-[22px] font-semibold leading-tight tracking-[-0.02em] text-fg-0",children:[c,t&&e.jsx("span",{className:"ml-2",children:l(t)})]}),s&&e.jsx("p",{className:"mt-1 max-w-3xl text-[12.5px] leading-snug text-fg-3",children:s})]})]}),a&&e.jsx("div",{className:"shrink-0",children:a})]})}const N={sm:"text-[11px]",md:"text-[11.5px]"};let p=!1;function H({head:c,children:n,minWidth:s,maxHeight:t,stickyHead:a,size:o="md",fit:l,zebra:f,padded:d,className:g,tableClassName:v}){var x,h;const b=a&&t!==void 0,y=(h=(x=globalThis.process)==null?void 0:x.env)==null?void 0:h.NODE_ENV;return a&&t===void 0&&!p&&y!=="production"&&(p=!0,console.warn("Table: stickyHead has no effect without maxHeight")),e.jsx("div",{className:r("overflow-x-auto",t!==void 0&&"overflow-y-auto",g),style:t!==void 0?{maxHeight:t}:void 0,children:e.jsxs("table",{className:r("border-collapse text-left",l?"w-auto":"w-full",N[o],v),style:s!==void 0?{minWidth:s}:void 0,children:[c!==void 0&&e.jsx("thead",{className:r("text-[10px] uppercase tracking-[0.06em] text-fg-3 [&_th]:border-b [&_th]:border-line-2",b&&"sticky top-0 z-[1] bg-bg-2",d&&"[&_th]:px-cell [&_th]:py-head"),children:c}),e.jsx("tbody",{className:r("[&>tr]:transition-colors [&>tr:hover]:bg-bg-3",f&&"[&>tr:nth-child(even)]:bg-bg-3/50",d&&"[&>tr>td]:px-cell [&>tr>td]:py-row"),children:n})]})})}export{S as C,_ as P,H as T,C as a,E as b,w as u};
