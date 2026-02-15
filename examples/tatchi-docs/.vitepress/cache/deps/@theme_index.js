import __buffer_polyfill from 'vite-plugin-node-polyfills/shims/buffer'
globalThis.Buffer = globalThis.Buffer || __buffer_polyfill
import __global_polyfill from 'vite-plugin-node-polyfills/shims/global'
globalThis.global = globalThis.global || __global_polyfill
import __process_polyfill from 'vite-plugin-node-polyfills/shims/process'
globalThis.process = globalThis.process || __process_polyfill

import {
  useMediaQuery
} from "./chunk-6F36HJN3.js";
import {
  computed,
  ref,
  shallowRef,
  watch
} from "./chunk-B7NEW2LT.js";
import {
  __toESM,
  init_define_process_env,
  require_dist,
  require_dist2,
  require_dist3
} from "./chunk-P56LWUW6.js";

// ../../node_modules/vitepress/dist/client/theme-default/index.js
init_define_process_env();
var import_dist28 = __toESM(require_dist());
var import_dist29 = __toESM(require_dist2());
var import_dist30 = __toESM(require_dist3());
import "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/styles/fonts.css";

// ../../node_modules/vitepress/dist/client/theme-default/without-fonts.js
init_define_process_env();
var import_dist25 = __toESM(require_dist(), 1);
var import_dist26 = __toESM(require_dist2(), 1);
var import_dist27 = __toESM(require_dist3(), 1);
import "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/styles/vars.css";
import "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/styles/base.css";
import "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/styles/icons.css";
import "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/styles/utils.css";
import "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/styles/components/custom-block.css";
import "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/styles/components/vp-code.css";
import "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/styles/components/vp-code-group.css";
import "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/styles/components/vp-doc.css";
import "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/styles/components/vp-sponsor.css";
import VPBadge from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPBadge.vue";
import Layout from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/Layout.vue";
import { default as default2 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPBadge.vue";
import { default as default3 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPButton.vue";
import { default as default4 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPDocAsideSponsors.vue";
import { default as default5 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPFeatures.vue";
import { default as default6 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPHomeContent.vue";
import { default as default7 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPHomeFeatures.vue";
import { default as default8 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPHomeHero.vue";
import { default as default9 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPHomeSponsors.vue";
import { default as default10 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPImage.vue";
import { default as default11 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPLink.vue";
import { default as default12 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPNavBarSearch.vue";
import { default as default13 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPSocialLink.vue";
import { default as default14 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPSocialLinks.vue";
import { default as default15 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPSponsors.vue";
import { default as default16 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPTeamMembers.vue";
import { default as default17 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPTeamPage.vue";
import { default as default18 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPTeamPageSection.vue";
import { default as default19 } from "/Users/pta/Dev/rust/simple-threshold-signer/node_modules/vitepress/dist/client/theme-default/components/VPTeamPageTitle.vue";

// ../../node_modules/vitepress/dist/client/theme-default/composables/local-nav.js
init_define_process_env();
var import_dist22 = __toESM(require_dist(), 1);
var import_dist23 = __toESM(require_dist2(), 1);
var import_dist24 = __toESM(require_dist3(), 1);
import { onContentUpdated } from "vitepress";

// ../../node_modules/vitepress/dist/client/theme-default/composables/outline.js
init_define_process_env();
var import_dist19 = __toESM(require_dist(), 1);
var import_dist20 = __toESM(require_dist2(), 1);
var import_dist21 = __toESM(require_dist3(), 1);
import { getScrollOffset } from "vitepress";

// ../../node_modules/vitepress/dist/client/theme-default/support/utils.js
init_define_process_env();
var import_dist7 = __toESM(require_dist(), 1);
var import_dist8 = __toESM(require_dist2(), 1);
var import_dist9 = __toESM(require_dist3(), 1);
import { withBase } from "vitepress";

// ../../node_modules/vitepress/dist/client/shared.js
init_define_process_env();
var import_dist = __toESM(require_dist(), 1);
var import_dist2 = __toESM(require_dist2(), 1);
var import_dist3 = __toESM(require_dist3(), 1);

// ../../node_modules/vitepress/dist/client/theme-default/composables/data.js
init_define_process_env();
var import_dist4 = __toESM(require_dist(), 1);
var import_dist5 = __toESM(require_dist2(), 1);
var import_dist6 = __toESM(require_dist3(), 1);
import { useData as useData$ } from "vitepress";
var useData = useData$;

// ../../node_modules/vitepress/dist/client/theme-default/support/utils.js
function ensureStartingSlash(path) {
  return path.startsWith("/") ? path : `/${path}`;
}

// ../../node_modules/vitepress/dist/client/theme-default/composables/aside.js
init_define_process_env();
var import_dist16 = __toESM(require_dist(), 1);
var import_dist17 = __toESM(require_dist2(), 1);
var import_dist18 = __toESM(require_dist3(), 1);

// ../../node_modules/vitepress/dist/client/theme-default/composables/sidebar.js
init_define_process_env();
var import_dist13 = __toESM(require_dist(), 1);
var import_dist14 = __toESM(require_dist2(), 1);
var import_dist15 = __toESM(require_dist3(), 1);

// ../../node_modules/vitepress/dist/client/theme-default/support/sidebar.js
init_define_process_env();
var import_dist10 = __toESM(require_dist(), 1);
var import_dist11 = __toESM(require_dist2(), 1);
var import_dist12 = __toESM(require_dist3(), 1);
function getSidebar(_sidebar, path) {
  if (Array.isArray(_sidebar))
    return addBase(_sidebar);
  if (_sidebar == null)
    return [];
  path = ensureStartingSlash(path);
  const dir = Object.keys(_sidebar).sort((a, b) => {
    return b.split("/").length - a.split("/").length;
  }).find((dir2) => {
    return path.startsWith(ensureStartingSlash(dir2));
  });
  const sidebar = dir ? _sidebar[dir] : [];
  return Array.isArray(sidebar) ? addBase(sidebar) : addBase(sidebar.items, sidebar.base);
}
function getSidebarGroups(sidebar) {
  const groups = [];
  let lastGroupIndex = 0;
  for (const index in sidebar) {
    const item = sidebar[index];
    if (item.items) {
      lastGroupIndex = groups.push(item);
      continue;
    }
    if (!groups[lastGroupIndex]) {
      groups.push({ items: [] });
    }
    groups[lastGroupIndex].items.push(item);
  }
  return groups;
}
function addBase(items, _base) {
  return [...items].map((_item) => {
    const item = { ..._item };
    const base = item.base || _base;
    if (base && item.link)
      item.link = base + item.link;
    if (item.items)
      item.items = addBase(item.items, base);
    return item;
  });
}

// ../../node_modules/vitepress/dist/client/theme-default/composables/sidebar.js
function useSidebar() {
  const { frontmatter, page, theme: theme2 } = useData();
  const is960 = useMediaQuery("(min-width: 960px)");
  const isOpen = ref(false);
  const _sidebar = computed(() => {
    const sidebarConfig = theme2.value.sidebar;
    const relativePath = page.value.relativePath;
    return sidebarConfig ? getSidebar(sidebarConfig, relativePath) : [];
  });
  const sidebar = ref(_sidebar.value);
  watch(_sidebar, (next, prev) => {
    if (JSON.stringify(next) !== JSON.stringify(prev))
      sidebar.value = _sidebar.value;
  });
  const hasSidebar = computed(() => {
    return frontmatter.value.sidebar !== false && sidebar.value.length > 0 && frontmatter.value.layout !== "home";
  });
  const leftAside = computed(() => {
    if (hasAside)
      return frontmatter.value.aside == null ? theme2.value.aside === "left" : frontmatter.value.aside === "left";
    return false;
  });
  const hasAside = computed(() => {
    if (frontmatter.value.layout === "home")
      return false;
    if (frontmatter.value.aside != null)
      return !!frontmatter.value.aside;
    return theme2.value.aside !== false;
  });
  const isSidebarEnabled = computed(() => hasSidebar.value && is960.value);
  const sidebarGroups = computed(() => {
    return hasSidebar.value ? getSidebarGroups(sidebar.value) : [];
  });
  function open() {
    isOpen.value = true;
  }
  function close() {
    isOpen.value = false;
  }
  function toggle() {
    isOpen.value ? close() : open();
  }
  return {
    isOpen,
    sidebar,
    sidebarGroups,
    hasSidebar,
    hasAside,
    leftAside,
    isSidebarEnabled,
    open,
    close,
    toggle
  };
}

// ../../node_modules/vitepress/dist/client/theme-default/composables/outline.js
var ignoreRE = /\b(?:VPBadge|header-anchor|footnote-ref|ignore-header)\b/;
var resolvedHeaders = [];
function getHeaders(range) {
  const headers = [
    ...document.querySelectorAll(".VPDoc :where(h1,h2,h3,h4,h5,h6)")
  ].filter((el) => el.id && el.hasChildNodes()).map((el) => {
    const level = Number(el.tagName[1]);
    return {
      element: el,
      title: serializeHeader(el),
      link: "#" + el.id,
      level
    };
  });
  return resolveHeaders(headers, range);
}
function serializeHeader(h) {
  let ret = "";
  for (const node of h.childNodes) {
    if (node.nodeType === 1) {
      if (ignoreRE.test(node.className))
        continue;
      ret += node.textContent;
    } else if (node.nodeType === 3) {
      ret += node.textContent;
    }
  }
  return ret.trim();
}
function resolveHeaders(headers, range) {
  if (range === false) {
    return [];
  }
  const levelsRange = (typeof range === "object" && !Array.isArray(range) ? range.level : range) || 2;
  const [high, low] = typeof levelsRange === "number" ? [levelsRange, levelsRange] : levelsRange === "deep" ? [2, 6] : levelsRange;
  return buildTree(headers, high, low);
}
function buildTree(data, min, max) {
  resolvedHeaders.length = 0;
  const result = [];
  const stack = [];
  data.forEach((item) => {
    const node = { ...item, children: [] };
    let parent = stack[stack.length - 1];
    while (parent && parent.level >= node.level) {
      stack.pop();
      parent = stack[stack.length - 1];
    }
    if (node.element.classList.contains("ignore-header") || parent && "shouldIgnore" in parent) {
      stack.push({ level: node.level, shouldIgnore: true });
      return;
    }
    if (node.level > max || node.level < min)
      return;
    resolvedHeaders.push({ element: node.element, link: node.link });
    if (parent)
      parent.children.push(node);
    else
      result.push(node);
    stack.push(node);
  });
  return result;
}

// ../../node_modules/vitepress/dist/client/theme-default/composables/local-nav.js
function useLocalNav() {
  const { theme: theme2, frontmatter } = useData();
  const headers = shallowRef([]);
  const hasLocalNav = computed(() => {
    return headers.value.length > 0;
  });
  onContentUpdated(() => {
    headers.value = getHeaders(frontmatter.value.outline ?? theme2.value.outline);
  });
  return {
    headers,
    hasLocalNav
  };
}

// ../../node_modules/vitepress/dist/client/theme-default/without-fonts.js
var theme = {
  Layout,
  enhanceApp: ({ app }) => {
    app.component("Badge", VPBadge);
  }
};
var without_fonts_default = theme;
export {
  default2 as VPBadge,
  default3 as VPButton,
  default4 as VPDocAsideSponsors,
  default5 as VPFeatures,
  default6 as VPHomeContent,
  default7 as VPHomeFeatures,
  default8 as VPHomeHero,
  default9 as VPHomeSponsors,
  default10 as VPImage,
  default11 as VPLink,
  default12 as VPNavBarSearch,
  default13 as VPSocialLink,
  default14 as VPSocialLinks,
  default15 as VPSponsors,
  default16 as VPTeamMembers,
  default17 as VPTeamPage,
  default18 as VPTeamPageSection,
  default19 as VPTeamPageTitle,
  without_fonts_default as default,
  useLocalNav,
  useSidebar
};
//# sourceMappingURL=@theme_index.js.map
