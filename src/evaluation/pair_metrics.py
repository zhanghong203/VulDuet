from sklearn.metrics import confusion_matrix


class AdvancedMetrics:
    """
    Compute custom evaluation metrics.

    Includes:
        - Balanced Recall
        - Balanced Precision
        - Pair Accuracy
    """

    @staticmethod
    def balanced_recall(labels, predictions):

        tn, fp, fn, tp = confusion_matrix(
            labels,
            predictions,
            labels=[0, 1]
        ).ravel()

        positive_recall = (
            tp / (tp + fn)
            if (tp + fn) > 0
            else 0.0
        )

        negative_recall = (
            tn / (tn + fp)
            if (tn + fp) > 0
            else 0.0
        )

        return (positive_recall + negative_recall) / 2

    @staticmethod
    def balanced_precision(labels, predictions):

        tn, fp, fn, tp = confusion_matrix(
            labels,
            predictions,
            labels=[0, 1]
        ).ravel()

        positive_precision = (
            tp / (tp + fp)
            if (tp + fp) > 0
            else 0.0
        )

        negative_precision = (
            tn / (tn + fn)
            if (tn + fn) > 0
            else 0.0
        )

        return (positive_precision + negative_precision) / 2

    @staticmethod
    def pair_accuracy(pair_results):
        """
        Parameters
        ----------
        pair_results : list[dict]

        每个元素格式：

        {
            "before_label": 1,
            "after_label": 0,
            "before_prediction": 1,
            "after_prediction": 0
        }

        Returns
        -------
        float
        """

        if len(pair_results) == 0:
            return 0.0

        correct = 0

        for pair in pair_results:

            before_ok = (
                pair["before_label"] ==
                pair["before_prediction"]
            )

            after_ok = (
                pair["after_label"] ==
                pair["after_prediction"]
            )

            if before_ok and after_ok:
                correct += 1

        return correct / len(pair_results)

    @staticmethod
    def evaluate(labels, predictions, pair_results=None):
        """
        Compute all advanced metrics.
        """

        result = {

            "balanced_recall":
                AdvancedMetrics.balanced_recall(
                    labels,
                    predictions
                ),

            "balanced_precision":
                AdvancedMetrics.balanced_precision(
                    labels,
                    predictions
                )
        }

        if pair_results is not None:

            result["pair_accuracy"] = \
                AdvancedMetrics.pair_accuracy(
                    pair_results
                )

        return result
