namespace OpenCertServer.Acme.Abstractions.HttpModel
{
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Represents a list of order urls
    /// </summary>
    public sealed class OrdersList
    {
        public OrdersList(IEnumerable<string> orders)
        {
            Orders = orders.ToList();
        }

        public List<string> Orders { get; set; }
    }
}
