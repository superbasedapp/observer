/**
 * Side-effect entry: `import "@superbased/feedback-widget/define"` registers
 * `<superbased-feedback>` (in a browser; a no-op elsewhere).
 */
import { defineFeedbackElement } from "./index.js";

defineFeedbackElement();

export { TAG } from "./index.js";
